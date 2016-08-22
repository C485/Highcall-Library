#include "../include/hcinternal.h"
#include "../include/hcprocess.h"
#include "../include/hcstring.h"
#include "../include/hcvirtual.h"

mem_result
HCAPI
HcInternalMemoryTest(SIZE_T dwBaseAddress,
	SIZE_T dwBufferLength)
{
	mem_result _result = { 0 };
	_result.address = dwBaseAddress;
	_result.length = 0;
	_result.accessible = TRUE;

	if (!dwBaseAddress)
	{
		_result.accessible = FALSE;
	}

	__try
	{
		/* try reading each piece of memory specified */
		for (SIZE_T Count = 0; Count < dwBufferLength; Count++)
		{
			if (dwBufferLength + Count)
			{
				_result.length++;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* we hit an inaccessible memory region */
		_result.accessible = FALSE;

		/* return immedietly */
		return _result;
	}

	return _result;
}

mem_result
HCAPI
HcInternalMemoryTestEx(SIZE_T dwBaseAddress,
	SIZE_T* pdwOffsets,
	SIZE_T dwOffsetCount,
	SIZE_T dwBufferLength)
{
	mem_result _result = { 0 };
	_result.address = dwBaseAddress;
	_result.length = 0;
	_result.accessible = TRUE;

	if (!dwBaseAddress)
	{
		_result.accessible = FALSE;
	}

	__try
	{
		if (!dwBaseAddress)
		{
			return _result;
		}

		/* start reading offsets to find the pointer, alternatively this could be done with mem_get_ptr() */
		_result.address = *(SIZE_T*)dwBaseAddress;
		for (unsigned int i = 0; i < dwOffsetCount - 1; i++)
		{
			if (!_result.address)
			{
				return _result;
			}

			_result.address = *(SIZE_T*)(_result.address + pdwOffsets[i]);
		}

		_result.address = (SIZE_T)_result.address + pdwOffsets[dwOffsetCount - 1];

		/* try reading each piece of memory specified */
		for (SIZE_T Count = 0; Count < dwBufferLength; Count++)
		{
			if (dwBufferLength + Count)
			{
				_result.length++;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* we hit inacessible memory */
		_result.accessible = FALSE;
		return _result;
	}

	return _result;
}

BOOLEAN
HCAPI
HcInternalMainModule(PHC_MODULE_INFORMATION moduleInfo)
{
	/* Query main module */
	return HcProcessQueryInformationModule(NtCurrentProcess,
		NULL,
		moduleInfo);
}

LPCSTR
HCAPI
HcInternalReadStringEx(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount)
{
	if (!memAddress)
		return 0;

	/* unsafe, can cause crash */
	SIZE_T address = *(SIZE_T*)memAddress;
	for (UINT i = 0; i < offsetCount - 1; i++)
	{
		if (!address)
			return 0;

		/* unsafe, can cause crash */
		address = *(SIZE_T*)(address + ptrOffsets[i]);
	}

	if (!address)
		return 0;

	return (const char*)(address + ptrOffsets[offsetCount - 1]);
}

LPCSTR
HCAPI
HcInternalReadString(SIZE_T memAddress)
{
	return (const char*) *(SIZE_T*)memAddress;
}

SIZE_T
HCAPI
HcInternalReadIntEx(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount)
{
	if (!memAddress)
		return 0;

	/* unsafe, can cause crash */
	SIZE_T address = *(SIZE_T*)memAddress;
	for (UINT i = 0; i < offsetCount; i++)
	{
		if (!address)
			return 0;

		/* unsafe, can cause crash */
		address = *(SIZE_T*)(address + ptrOffsets[i]);
	}

	return address;
}

SIZE_T
HCAPI
HcInternalReadInt(SIZE_T baseAddress)
{
	return (SIZE_T)*(SIZE_T*)baseAddress;
}

SIZE_T
HCAPI
HcInternalLocatePointer(SIZE_T baseAddress, SIZE_T* offsets, unsigned int offsetCount)
{
	if (!baseAddress)
		return baseAddress;

	/* unsafe, can cause crash */
	SIZE_T address = *(SIZE_T*)baseAddress;
	for (unsigned int i = 0; i < offsetCount - 1; i++)
	{
		if (!address)
			return 0;

		/* unsafe, can cause crash */
		address = *(SIZE_T*)(address + offsets[i]);
	}

	if (!address)
		return 0;

	return (SIZE_T)address + offsets[offsetCount - 1];
}

VOID
HCAPI
HcInternalMemoryWrite(PVOID pAddress, SIZE_T dwLen, BYTE* ptrWrite)
{
	DWORD dwProtection;

	/* change the protection to something we can write to */
	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwProtection);

	/* write the memory */
	memcpy(pAddress, ptrWrite, dwLen);

	/* restore the protection */
	VirtualProtect(pAddress, dwLen, dwProtection, &dwProtection);
}

VOID
HCAPI
HcInternalMemoryNop(PVOID pAddress, SIZE_T dwLen)
{
	DWORD dwProtection;

	/* change the protection to something we can write to */
	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwProtection);

	/* write the nops */
	memset(pAddress, 0x90, dwLen);

	/* restore the protection */
	VirtualProtect(pAddress, dwLen, dwProtection, &dwProtection);
}

SIZE_T
HCAPI
HcInternalPatternFind(LPCSTR pattern, LPCSTR mask, HC_MODULE_INFORMATION module)
{
	/* specifies where the function will start searching from */
	SIZE_T base = module.Base;

	/* specifies where the function will end searching */
	SIZE_T size = module.Size;

	/* Size of our pattern's mask. */
	DWORD MaskSize = HcStringSecureLengthA(mask);

	/* loop through the specified module */
	for (SIZE_T retAddress = base; retAddress < base + size - MaskSize; retAddress++)
	{
		if (*(BYTE*)retAddress == (pattern[0] & 0xff) || mask[0] == '?')
		{
			SIZE_T startSearch = retAddress;
			for (int i = 0; mask[i] != '\0'; i++, startSearch++)
			{
				/* next */
				if ((pattern[i] & 0xff) != *(BYTE*)startSearch && mask[i] != '?')
					break;

				/* is it a match? */
				if (((pattern[i] & 0xff) == *(BYTE*)startSearch || mask[i] == '?') && mask[i + 1] == '\0')
					return retAddress;
			}
		}
	}

	return 0;
}
