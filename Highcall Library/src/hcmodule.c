#include "../include/hcmodule.h"
#include "../include/hcstring.h"
#include "../include/hcimport.h"
#include "../include/hctrampoline.h"

/*
@implemented
*/
SIZE_T
HCAPI
HcModuleProcedureAddressA(HANDLE hModule, LPCSTR lpProcedureName)
{
	IMAGE_NT_HEADERS* pHeaderNT;
	IMAGE_DOS_HEADER* pHeaderDOS;
	IMAGE_EXPORT_DIRECTORY* pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPCSTR lpCurrentFunction;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	pHeaderDOS = (PIMAGE_DOS_HEADER)hModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	SIZE_T dwModule = (SIZE_T)hModule;

	pHeaderNT = (PIMAGE_NT_HEADERS)(pHeaderDOS->e_lfanew + dwModule);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	pExports = (IMAGE_EXPORT_DIRECTORY*)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + dwModule);

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + dwModule);
	if (!pExportNames)
	{
		return 0;
	}

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPCSTR)(pExportNames[i] + dwModule);
		if (!lpCurrentFunction)
		{
			continue;
		}

		/* Check for a match*/
		if (HcStringEqualA(lpCurrentFunction, lpProcedureName, TRUE))
		{
			pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + dwModule);
			pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + dwModule);

			return pExportFunctions[pExportOrdinals[i]] + dwModule;
		}
	}

	return 0;
}

/*
@implemented
*/
SIZE_T
HCAPI
HcModuleProcedureAddressW(HANDLE hModule, LPCWSTR lpProcedureName)
{
	DWORD Size;
	SIZE_T ReturnValue;
	LPSTR lpConvertedName;

	Size = HcStringSecureLengthW(lpProcedureName);
	if (!Size)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		return 0;
	}

	lpConvertedName = (LPSTR)VirtualAlloc(0,
		Size + 1,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!lpConvertedName)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES));
		return 0;
	}

	if (!HcStringConvertW(lpProcedureName, lpConvertedName, Size))
	{
		SetLastError(RtlNtStatusToDosError(STATUS_FAILED));
		VirtualFree(lpConvertedName, 0, MEM_RELEASE);
		return 0;
	}

	ReturnValue = HcModuleProcedureAddressA(hModule, lpConvertedName);

	VirtualFree(lpConvertedName, 0, MEM_RELEASE);
	return ReturnValue;
}

BOOLEAN 
HCAPI
HcModuleListExports(HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam)
{
	IMAGE_NT_HEADERS* pHeaderNT;
	IMAGE_DOS_HEADER* pHeaderDOS;
	IMAGE_EXPORT_DIRECTORY* pExports;
	PDWORD pExportNames;
	LPCSTR lpCurrentFunction;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	pHeaderDOS = (PIMAGE_DOS_HEADER)hModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	SIZE_T dwModule = (SIZE_T)hModule;

	pHeaderNT = (PIMAGE_NT_HEADERS)(pHeaderDOS->e_lfanew + dwModule);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	pExports = (IMAGE_EXPORT_DIRECTORY*)
		(pHeaderNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + dwModule);

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + dwModule);
	if (!pExportNames)
	{
		return 0;
	}

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfNames; i++)
	{
		lpCurrentFunction = (LPCSTR)(pExportNames[i] + dwModule);
		if (!lpCurrentFunction)
		{
			continue;
		}

		if (callback(lpCurrentFunction, lpParam))
		{
			return TRUE;
		}
	}

	return TRUE;
}

/*
@implemented
*/
HMODULE
HCAPI
HcModuleHandleW(LPCWSTR lpModuleName)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;

	/* if there is no name specified, return base address of main module */
	if (!lpModuleName)
	{
		return ((HMODULE)pPeb->ImageBaseAddress);
	}

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (HcStringEqualW(lpModuleName, pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			return (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	return 0;
}

/*
@implemented
*/
HMODULE
HCAPI
HcModuleHandleA(LPCSTR lpModuleName)
{
	DWORD Size;
	HMODULE ReturnValue;
	LPWSTR lpConvertedName;

	Size = HcStringSecureLengthA(lpModuleName);
	if (!Size)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		return 0;
	}

	lpConvertedName = (LPWSTR)VirtualAlloc(0,
		Size + 1,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!lpConvertedName)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES));
		return 0;
	}

	if (!HcStringConvertA(lpModuleName, lpConvertedName, Size))
	{
		SetLastError(STATUS_FAILED);
		VirtualFree(lpConvertedName, 0, MEM_RELEASE);
		return 0;
	}

	ReturnValue = HcModuleHandleW(lpConvertedName);

	VirtualFree(lpConvertedName, 0, MEM_RELEASE);
	return ReturnValue;
}


HMODULE
HCAPI
HcModuleLoadA(LPCSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	DWORD Length;
	LPWSTR lpConverted;
	HANDLE hModule;

	if (HcStringIsBadA(lpPath))
	{
		return 0;
	}

	Length = HcStringSecureLengthA(lpPath);
	if (!Length)
	{
		return 0;
	}

	lpConverted = (LPWSTR)VirtualAlloc(NULL,
		Length + 1,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!lpConverted)
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	if (!HcStringConvertA(lpPath, lpConverted, Length))
	{
		VirtualFree(lpConverted, 0, MEM_RELEASE);
		return 0;
	}

	RtlInitUnicodeString(&Path, lpConverted);

	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(Status);
		VirtualFree(lpConverted, 0, MEM_RELEASE);

		return 0;
	}

	VirtualFree(lpConverted, 0, MEM_RELEASE);
	return (HMODULE)hModule;
}

HMODULE
HCAPI
HcModuleLoadW(LPCWSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	HANDLE hModule;

	if (HcStringIsBadW(lpPath))
	{
		return 0;
	}

	RtlInitUnicodeString(&Path, lpPath);

	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(Status);
		return 0;
	}

	return (HMODULE)hModule;
}