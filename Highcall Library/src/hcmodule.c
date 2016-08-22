#include "../include/hcmodule.h"
#include "../include/hcstring.h"
#include "../include/hcimport.h"
#include "../include/hctrampoline.h"
#include "../include/hcpe.h"
#include "../include/hcvirtual.h"

/*
@implemented
*/
SIZE_T
HCAPI
HcModuleProcedureAddressA(HANDLE hModule, LPCSTR lpProcedureName)
{
	SIZE_T szModule;
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	PDWORD pExportFunctions;
	PWORD pExportOrdinals;
	LPCSTR lpCurrentFunction;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	szModule = (SIZE_T)hModule;

	pExports = HcPEGetExportDirectory(hModule);
	if (!pExports)
	{
		return 0;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + szModule);

	/* List through functions */
	for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
	{
		lpCurrentFunction = (LPCSTR)(pExportNames[i] + szModule);
		if (!lpCurrentFunction)
		{
			continue;
		}

		/* Check for a match*/
		if (HcStringEqualA(lpCurrentFunction, lpProcedureName, TRUE))
		{
			pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + szModule);
			pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + szModule);

			return pExportFunctions[pExportOrdinals[i]] + szModule;
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

	lpConvertedName = (LPSTR)HcAlloc(Size + 1);

	if (!lpConvertedName)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES));
		return 0;
	}

	if (!HcStringConvertW(lpProcedureName, lpConvertedName, Size))
	{
		SetLastError(RtlNtStatusToDosError(STATUS_FAILED));
		HcFree(lpConvertedName);
		return 0;
	}

	ReturnValue = HcModuleProcedureAddressA(hModule, lpConvertedName);

	HcFree(lpConvertedName);
	return ReturnValue;
}

BOOLEAN 
HCAPI
HcModuleListExports(HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam)
{
	PIMAGE_EXPORT_DIRECTORY pExports;
	PDWORD pExportNames;
	LPCSTR lpCurrentFunction;
	SIZE_T dwModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	dwModule = (SIZE_T)hModule;

	pExports = HcPEGetExportDirectory(hModule);
	if (!pExports)
	{
		return FALSE;
	}

	/* Get the address containg null terminated export names, in ASCII */
	pExportNames = (PDWORD)(pExports->AddressOfNames + dwModule);
	if (!pExportNames)
	{
		return FALSE;
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

	lpConvertedName = (LPWSTR)HcAlloc(Size + 1);
	if (!lpConvertedName)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES));
		return 0;
	}

	if (!HcStringConvertA(lpModuleName, lpConvertedName, Size))
	{
		SetLastError(STATUS_FAILED);
		HcFree(lpConvertedName);
		return 0;
	}

	ReturnValue = HcModuleHandleW(lpConvertedName);

	HcFree(lpConvertedName);
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

	lpConverted = (LPWSTR)HcAlloc(Length + 1);
	if (!lpConverted)
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	if (!HcStringConvertA(lpPath, lpConverted, Length))
	{
		HcFree(lpConverted);
		return 0;
	}

	RtlInitUnicodeString(&Path, lpConverted);

	Status = LdrLoadDll(0, 0, &Path, &hModule);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(Status);
		HcFree(lpConverted);

		return 0;
	}

	HcFree(lpConverted);
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
