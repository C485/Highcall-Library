#define _CRT_SECURE_NO_WARNINGS

/* GetModuleFileName should be replaced */

#include <ctime>
#include <stdio.h>


#include "hcapi.h"
#include "highcall.h"
#include "hcsyscall.h"
#include "hcimport.h"
#include "hctrampoline.h"

/*
@implemented
*/
BOOL
HCAPI
HcStringIsBad(LPCSTR lpcStr)
{
	if (!lpcStr)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	__try
	{
		for (; *lpcStr; *lpcStr++)
		{
			if (!*lpcStr)
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	return FALSE;
}

/*
@implemented
*/
BOOL
HCAPI
HcStringIsBad(LPCWSTR lpcStr)
{
	if (!lpcStr)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	__try
	{
		for (; *lpcStr; *lpcStr++)
		{
			if (!*lpcStr)
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	return FALSE;
}

/*
@implemented
*/
LPSTR*
HCAPI
HcStringSplit(LPSTR lpStr, const char cDelimiter, PSIZE_T pdwCount)
{
	LPSTR* plpResult;
	LPSTR lpCopy;
	LPSTR LastDelimiter;
	LPSTR lpToken;
	SIZE_T Count;
	SIZE_T Index;
	char lpTerminatedDelim[2];

	if (HcStringIsBad(lpStr))
	{
		return 0;
	}

	/* Set the pointer to the copy. */
	if (!(lpCopy = lpStr))
	{
		return 0;
	}

	Count = 0;
	LastDelimiter = 0;

	/* Null terminate the delimiter. */
	lpTerminatedDelim[0] = cDelimiter;
	lpTerminatedDelim[1] = 0;

	/* Test the copy for the final delimiter location, set the count. */
	while (*lpCopy)
	{
		if (cDelimiter == *lpCopy)
		{
			Count++;
			LastDelimiter = lpCopy;
		}
		lpCopy++;
	}

	Count += LastDelimiter < (lpStr + strlen(lpStr) - 1);
	Count++;

	if (!(plpResult = (LPSTR*)VirtualAlloc(NULL,
		sizeof(LPSTR) * Count,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE)))
	{
		return 0;
	}

	/* Get the first token. */
	lpToken = strtok(lpStr, lpTerminatedDelim);

	Index = 0;
	*pdwCount = 0;

	/* Loop over the splits. */
	while (lpToken)
	{
		ASSERT(Index < Count);

		/* Duplicate the string and insert into return array. */
		*(plpResult + Index++) = _strdup(lpToken);
		*pdwCount += 1;

		/* Acquire next token. */
		lpToken = strtok(0, lpTerminatedDelim);
	}
	ASSERT(Index == Count - 1);

	/* Null terminate final string. */
	*(plpResult + Index) = 0;

	return plpResult;
}

/*
@implemented
*/
VOID
HCAPI
HcStringSplitToIntArray(LPSTR lpStr, const char delim, int* pArray, PSIZE_T dwCount)
{
	LPSTR* plpSplit;
	SIZE_T Count;
	if (HcStringIsBad(lpStr))
	{
		return;
	}

	/* Acquire the split. */
	plpSplit = HcStringSplit(lpStr, delim, &Count);
	if (!plpSplit)
	{
		return;
	}

	__try
	{
		/* get the length of the array */
		for (SIZE_T i = 0; dwCount; i++)
		{
			pArray[i] = atoi(plpSplit[i]);
			*dwCount += 1;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(STATUS_INFO_LENGTH_MISMATCH);
		return;
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringIntToStringArray(int pIntArray[], SIZE_T dwCountToRead, LPSTR* lpOutStringArray)
{
	LPSTR lpCurrent;

	/* Loop the count. */
	for (SIZE_T i = 0; i < dwCountToRead; i++)
	{
		/* Allocate next. */
		lpCurrent = (LPSTR)VirtualAlloc(0,
			MAX_INT_STRING,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		__try
		{

			/* Parste the content. */
			sprintf(lpCurrent, "%d", pIntArray[i]);

			/* Terminate the last character. */
			lpCurrent[9] = 0;

			/* move the string into the array */
			strncpy(lpOutStringArray[i], lpCurrent, MAX_INT_STRING);

			VirtualFree(lpCurrent, 0, MEM_RELEASE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			VirtualFree(lpCurrent, 0, MEM_RELEASE);
			SetLastError(STATUS_PARTIAL_COPY);
			return;
		}
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringSubtract(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T dwIndex, SIZE_T dwEndIndex, size_t lpSize)
{
	if (HcStringIsBad(lpStr))
	{
		return;
	}

	/* Create the null terminated sub string. */
	if (strncpy(lpOutStr, lpStr + dwIndex, dwEndIndex - dwIndex))
	{
		lpOutStr[dwEndIndex - dwIndex] = ANSI_NULL;
	}
}

SIZE_T
HCAPI
HcStringCharIndex(LPCSTR lpStr, char delim)
{
	if (HcStringIsBad(lpStr))
	{
		return -1;
	}

	LPCSTR pch = strrchr(lpStr, delim);
	return pch ? pch - lpStr + 1 : -1;
}

/*
@implemented
@will be reimplmeneted
*/
LPCSTR
HCAPI
HcStringTime()
{
	time_t rawtime;
	time(&rawtime);
	struct tm timeinfo;
	localtime_s(&timeinfo, &rawtime);
	char* buffer = (char*)malloc(80);
	strftime(buffer, 80, "%d-%m-%Y %I:%M:%S", &timeinfo);
	return buffer;
}

/*
@implemented
*/
VOID
HCAPI
HcStringToLower(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = tolower(*lpStr);
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringToLower(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = tolower(*lpStr);
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringToUpper(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = toupper(*lpStr);
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringToUpper(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = toupper(*lpStr);
	}
}
/*
@implemented
*/
BOOL
HCAPI
HcStringEqual(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = strlen(lpString1);
	Size2 = strlen(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPSTR lpCopy1, lpCopy2;

		lpCopy1 = (LPSTR)VirtualAlloc(0,
			Size1,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		strncpy(lpCopy1, lpString1, Size1);
		HcStringToLower(lpCopy1);

		lpCopy2 = (LPSTR)VirtualAlloc(0,
			Size2,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		strncpy(lpCopy2, lpString2, Size2);
		HcStringToLower(lpCopy2);

		Return = strcmp(lpCopy1, lpCopy2);

		VirtualFree(lpCopy1, 0, MEM_RELEASE);
		VirtualFree(lpCopy2, 0, MEM_RELEASE);

		return !Return;
	}

	return !strcmp(lpString1, lpString2);
}

/*
@implemented
*/
BOOL
HCAPI
HcStringEqual(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = wcslen(lpString1);
	Size2 = wcslen(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1, lpCopy2;

		lpCopy1 = (LPWSTR)VirtualAlloc(0,
			Size1,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		wcsncpy(lpCopy1, lpString1, Size1);
		HcStringToLower(lpCopy1);

		lpCopy2 = (LPWSTR)VirtualAlloc(0,
			Size2,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		wcsncpy(lpCopy2, lpString2, Size2);
		HcStringToLower(lpCopy2);

		Return = wcscmp(lpCopy1, lpCopy2);

		VirtualFree(lpCopy1, 0, MEM_RELEASE);
		VirtualFree(lpCopy2, 0, MEM_RELEASE);

		return !Return;
	}

	return !wcscmp(lpString1, lpString2);
}

NTSTATUS
HCAPI
HcGetTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated
) {
	NTSTATUS Status;
	TOKEN_ELEVATION Elevation;
	ULONG returnLength;

	Status = HcQueryInformationToken(TokenHandle,
		TokenElevation,
		&Elevation,
		sizeof(TOKEN_ELEVATION),
		&returnLength);

	if (NT_SUCCESS(Status))
	{
		*Elevated = !!Elevation.TokenIsElevated;
	}

	return Status;
}

/*
@implemented
*/
SIZE_T
HCAPI
HcGetProcedureAddress(HANDLE hModule, LPCSTR lpProcedureName)
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
		if (HcStringEqual(lpCurrentFunction, lpProcedureName, TRUE))
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
HcGetProcedureAddress(HANDLE hModule, LPCWSTR lpProcedureName)
{
	DWORD Size;
	SIZE_T ReturnValue;
	LPSTR lpConvertedName;

	if (!(Size = WideCharToMultiByte(CP_UTF8, 0, lpProcedureName, -1, NULL, 0, NULL, NULL)))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return 0;
	}

	if (!(lpConvertedName = (LPSTR)VirtualAlloc(0,
		Size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE)))
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	if (!(WideCharToMultiByte(CP_UTF8, 0, lpProcedureName, -1, lpConvertedName, Size, NULL, NULL)))
	{
		SetLastError(STATUS_FAILED);
		VirtualFree(lpConvertedName, 0, MEM_RELEASE);
		return 0;
	}

	ReturnValue = HcGetProcedureAddress(hModule, lpConvertedName);

	VirtualFree(lpConvertedName, 0, MEM_RELEASE);
	return ReturnValue;
}

/*
@implemented
*/
HMODULE
HCAPI
HcGetModuleHandle(LPCWSTR lpModuleName)
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
		if (HcStringEqual(lpModuleName, pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
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
HcGetModuleHandle(LPCSTR lpModuleName)
{
	DWORD Size;
	HMODULE ReturnValue;
	LPWSTR lpConvertedName;

	if (!(Size = MultiByteToWideChar(CP_UTF8, 0, lpModuleName, -1, NULL, 0)))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return 0;
	}

	if (!(lpConvertedName = (LPWSTR)VirtualAlloc(0,
		Size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE)))
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	if (!(MultiByteToWideChar(CP_UTF8, 0, lpModuleName, -1, lpConvertedName, Size)))
	{
		SetLastError(STATUS_FAILED);
		VirtualFree(lpConvertedName, 0, MEM_RELEASE);
		return 0;
	}

	ReturnValue = HcGetModuleHandle(lpConvertedName);

	VirtualFree(lpConvertedName, 0, MEM_RELEASE);
	return ReturnValue;
}

/*
@implemented
*/
DWORD
HCAPI
HcRVAToFileOffset(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageHeader);

	for (unsigned i = 0, sections = pImageHeader->FileHeader.NumberOfSections; i < sections; i++, sectionHeader++)
	{
		if (sectionHeader->VirtualAddress <= RVA)
		{
			if ((sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) > RVA)
			{
				RVA -= sectionHeader->VirtualAddress;
				RVA += sectionHeader->PointerToRawData;
				return (DWORD) RVA;
			}
		}
	}
	return 0;
}

/*
@implemented
*/
DWORD
HCAPI
HcExportToFileOffset(HMODULE hModule, LPCSTR lpExportName)
{
	PIMAGE_DOS_HEADER pHeaderDOS;
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T szExportRVA;
	SIZE_T szExportVA;
	SIZE_T szModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	pHeaderDOS = (PIMAGE_DOS_HEADER)hModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	szModule = (SIZE_T)hModule;

	pHeaderNT = (PIMAGE_NT_HEADERS)(szModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	szExportVA = (SIZE_T)HcGetProcedureAddress(hModule, lpExportName);
	if (szExportVA)
	{
		/* Calculate the relative offset */
		szExportRVA = szExportVA - szModule;

		return HcRVAToFileOffset(pHeaderNT, szExportRVA);
	}

	return 0;
}

/*
@implemented
*/
DWORD
HCAPI
HcExportToFileOffset(HMODULE hModule, LPCWSTR lpExportName)
{
	PIMAGE_DOS_HEADER pHeaderDOS;
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T dwExportRVA;
	SIZE_T dwExportVA;
	SIZE_T dwModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	pHeaderDOS = (PIMAGE_DOS_HEADER)hModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	dwModule = (SIZE_T)hModule;

	pHeaderNT = (PIMAGE_NT_HEADERS)(dwModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	dwExportVA = (SIZE_T)HcGetProcedureAddress(hModule, lpExportName);
	if (dwExportVA)
	{
		/* Calculate the relative offset */
		dwExportRVA = dwExportVA - dwModule;

		return HcRVAToFileOffset(pHeaderNT, dwExportRVA);
	}

	return 0;
}

/*
@implemented
@problem: can't call the native handle close.
*/
SIZE_T
HCAPI
HcReadFileModule(HMODULE hModule, LPCSTR lpExportName, BYTE* lpBuffer, DWORD dwCount)
{
	DWORD dwFileOffset;
	LPSTR lpModulePath;
	HANDLE hFile;
	DWORD BytesRead;

	if (!(dwFileOffset = HcExportToFileOffset(hModule, lpExportName)))
	{
		return 0;
	}

	if (!(lpModulePath = (LPSTR)VirtualAlloc(NULL,
		MAX_PATH,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE)))
	{
		return 0;
	}

	/* Acquire path of targetted module. */
	GetModuleFileNameA(hModule, lpModulePath, MAX_PATH);
	if (!lpModulePath)
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		return 0;
	}

	if (!(hFile = CreateFileA(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		return 0;
	}

	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	VirtualFree(lpModulePath, NULL, MEM_RELEASE);
	CloseHandle(hFile);
	return BytesRead;
}

/*
@implemented
@problem: can't call the native handle close.
*/
SIZE_T
HCAPI
HcReadFileModule(HMODULE hModule, LPCWSTR lpExportName, BYTE* lpBuffer, DWORD dwCount)
{
	DWORD dwFileOffset;
	LPWSTR lpModulePath;
	HANDLE hFile;
	DWORD BytesRead;

	if (!(dwFileOffset = HcExportToFileOffset(hModule, lpExportName)))
	{
		return 0;
	}

	if (!(lpModulePath = (LPWSTR)VirtualAlloc(NULL,
		MAX_PATH,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE)))
	{
		return 0;
	}

	/* Acquire path of targetted module. */
	GetModuleFileNameW(hModule, lpModulePath, MAX_PATH);
	if (!lpModulePath)
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		return 0;
	}

	if (!(hFile = CreateFileW(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		return 0;
	}

	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	VirtualFree(lpModulePath, NULL, MEM_RELEASE);
	CloseHandle(hFile);
	return BytesRead;
}

DWORD
HCAPI
HcVirtualAddressFileOffset(LPBYTE lpBaseAddress, HMODULE hModule)
{
	PIMAGE_DOS_HEADER pHeaderDOS;
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T dwRVA;
	SIZE_T dwModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	if (!lpBaseAddress)
	{
		return 0;
	}

	pHeaderDOS = (PIMAGE_DOS_HEADER)hModule;
	if (pHeaderDOS->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	dwModule = (SIZE_T)hModule;

	pHeaderNT = (PIMAGE_NT_HEADERS)(dwModule + pHeaderDOS->e_lfanew);
	if (pHeaderNT->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	/* Calculate the relative offset */
	dwRVA = ((SIZE_T) lpBaseAddress) - dwModule;

	return HcRVAToFileOffset(pHeaderNT, dwRVA);
}

SIZE_T
HCAPI
HcReadModuleAddressDisk(LPBYTE lpBaseAddress, PBYTE lpBufferOut, DWORD dwCountToRead)
{
	DWORD dwFileOffset;
	LPWSTR lpModulePath;
	HANDLE hFile;
	DWORD BytesRead;
	HMODULE hModule;
	MEMORY_BASIC_INFORMATION memInfo;

	/* Find the module that allocated the address */
	if (!HcVirtualQuery(NtCurrentProcess,
		lpBaseAddress,
		&memInfo,
		sizeof(memInfo)))
	{
		return 0;
	}

	/* Take the module */
	hModule = (HMODULE)memInfo.AllocationBase;
	if (!hModule)
	{
		return 0;
	}

	/* Get the file offset */
	dwFileOffset = HcVirtualAddressFileOffset(lpBaseAddress, hModule);
	if (!dwFileOffset)
	{
		return 0;
	}

	/* Allocate for the path of the module */
	lpModulePath = (LPWSTR)VirtualAlloc(NULL,
		MAX_PATH,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	if (!lpModulePath)
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		return 0;
	}

	/* Acquire path of targetted module. */
	GetModuleFileNameW(hModule, lpModulePath, MAX_PATH);
	if (!lpModulePath)
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		return 0;
	}

	/* Open the file */
	if (!(hFile = CreateFileW(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		return 0;
	}

	/* Go to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		HcCloseHandle(hFile);
		return 0;
	}

	/* Read it */
	if (!ReadFile(hFile, lpBufferOut, dwCountToRead, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, NULL, MEM_RELEASE);
		HcCloseHandle(hFile);
		return 0;
	}

	VirtualFree(lpModulePath, NULL, MEM_RELEASE);
	HcCloseHandle(hFile);
	return BytesRead;
}

/* Unreliable. */
SyscallIndex
HCAPI
HcSyscallIndex(LPCSTR lpName)
{
	BYTE buffer[10];
	HcReadFileModule(NTDLL, lpName, buffer, 10);

#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return buffer ? *(ULONG*)(buffer + 1) : 0;
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return buffer ? *(ULONG*)(buffer + 4) : 0;
#endif
}

/* Unreliable. */
SyscallIndex
HCAPI
HcSyscallIndex(LPCWSTR lpName)
{
	BYTE buffer[10];
	HcReadFileModule(NTDLL, lpName, buffer, 10);

#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return buffer ? *(ULONG*)(buffer + 1) : 0;
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return buffer ? *(ULONG*)(buffer + 4) : 0;
#endif
}

HANDLE
HCAPI
HcProcessOpen(SIZE_T dwProcessId, ACCESS_MASK DesiredAccess)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	HANDLE hProcess;

	cid.UniqueProcess = (HANDLE)dwProcessId;
	cid.UniqueThread = 0;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	Status = HcOpenProcess(&hProcess, DesiredAccess, &oa, &cid);

	SetLastError(Status);
	if (NT_SUCCESS(Status))
	{
		return hProcess;
	}

	return 0;
}

VOID
HCAPI
HcCloseHandle(HANDLE hObject)
{
	__try
	{
		HcClose(hObject);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* Doesn't really matter, It's either already closed or It was never even opened. */
		SetLastError(STATUS_FAILED);
	}
}

BOOL
HCAPI
HcProcessFree(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN ULONG dwFreeType)
{
	NTSTATUS Status;

	/* Validate size and flags */
	if (!dwSize || !(dwFreeType & MEM_RELEASE))
	{
		/* Free the memory */
		Status = HcFreeVirtualMemory(hProcess,
			&lpAddress,
			&dwSize,
			dwFreeType);

		if (!NT_SUCCESS(Status))
		{
			SetLastError(Status);
			return FALSE;
		}

		return TRUE;
	}

	SetLastError(STATUS_INVALID_PARAMETER);
	return FALSE;
}

/*
* @implemented
* removed SEH block
*/
LPVOID
HCAPI
HcProcessAllocate(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN ULONG flAllocationType,
	IN ULONG flProtect)
{
	NTSTATUS Status;

	Status = HcAllocateVirtualMemory(hProcess,
		&lpAddress,
		0,
		&dwSize,
		flAllocationType,
		flProtect);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(Status);
		return NULL;
	}

	return lpAddress;
}

BOOL
HCAPI
HcProcessWriteMemory(HANDLE hProcess,
	PVOID lpBaseAddress,
	CONST VOID* lpBuffer,
	ULONG nSize,
	PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue;
	SIZE_T RegionSize;
	PVOID Base;
	BOOLEAN UnProtect;

	/* Set parameters for protect call */
	RegionSize = nSize;
	Base = lpBaseAddress;

	/* Check the current status */
	Status = HcProtectVirtualMemory(hProcess,
		&Base,
		&RegionSize,
		PAGE_EXECUTE_READWRITE,
		&OldValue);

	SetLastError(Status);
	if (NT_SUCCESS(Status))
	{
		/* Check if we are unprotecting */
		UnProtect = OldValue & (PAGE_READWRITE |
			PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE |
			PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;

		if (!UnProtect)
		{
			/* Set the new protection */
			Status = HcProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Write the memory */
			Status = HcWriteVirtualMemory(hProcess,
				lpBaseAddress,
				(LPVOID)lpBuffer,
				nSize,
				&nSize);

			/* In Win32, the parameter is optional, so handle this case */
			if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

			if (!NT_SUCCESS(Status))
			{
				SetLastError(Status);
				return FALSE;
			}

			/* Flush the ITLB */
			HcFlushInstructionCache(hProcess, lpBaseAddress, nSize);
			return TRUE;
		}

		/* Check if we were read only */
		if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
		{
			/* Restore protection and fail */
			HcProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Note: This is what Windows returns and code depends on it */
			return STATUS_ACCESS_VIOLATION;
		}

		/* Otherwise, do the write */
		Status = HcWriteVirtualMemory(hProcess,
			lpBaseAddress,
			(LPVOID)lpBuffer,
			nSize,
			&nSize);

		/* In Win32, the parameter is optional, so handle this case */
		if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

		/* And restore the protection */
		HcProtectVirtualMemory(hProcess,
			&Base,
			&RegionSize,
			OldValue,
			&OldValue);

		if (!NT_SUCCESS(Status))
		{
			/* Note: This is what Windows returns and code depends on it */
			return STATUS_ACCESS_VIOLATION;
		}

		/* Flush the ITLB */
		HcFlushInstructionCache(hProcess, lpBaseAddress, nSize);
		return TRUE;
	}

	return FALSE;
}

BOOL
HCAPI
HcProcessReadMemory(IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesRead)
{
	NTSTATUS Status;

	/* Do the read */
	Status = HcReadVirtualMemory(hProcess,
		(PVOID)lpBaseAddress,
		lpBuffer,
		nSize,
		&nSize);

	/* In user-mode, this parameter is optional */
	if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		return FALSE;
	}

	/* Return success */
	return TRUE;
}


SIZE_T
NTAPI
HcVirtualQuery(IN HANDLE hProcess,
	IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	IN SIZE_T dwLength)
{
	NTSTATUS Status;
	SIZE_T ResultLength;

	/* Query basic information */
	Status = HcQueryVirtualMemory(hProcess,
		(LPVOID)lpAddress,
		MemoryBasicInformation,
		lpBuffer,
		dwLength,
		&ResultLength);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		SetLastError(Status);
		return 0;
	}

	/* Return the queried length */
	return ResultLength;
}

BOOL
HCAPI
HcProcessQueryInformationWindow(_In_ HANDLE ProcessHandle,
	PHC_WINDOW_INFORMATION HCWindowInformation)
{
	NTSTATUS Status;
	PVOID Buffer;
	ULONG ReturnLength;
	PPROCESS_WINDOW_INFORMATION WindowInformation;

	/* Query the length. */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessWindowInformation,
		NULL,
		NULL,
		&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		SetLastError(Status);
		return FALSE;
	}

	Buffer = VirtualAlloc(NULL,
		ReturnLength,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	WindowInformation = (PPROCESS_WINDOW_INFORMATION)Buffer;

	/* Get the window information. */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessWindowInformation,
		WindowInformation,
		ReturnLength,
		&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		HCWindowInformation->WindowFlags = WindowInformation->WindowFlags;

		/* Copy the window's title. */
		wcsncpy(HCWindowInformation->WindowTitle,
			WindowInformation->WindowTitle,
			WindowInformation->WindowTitleLength);

		VirtualFree(Buffer, 0, MEM_RELEASE);
		return TRUE;
	}

	VirtualFree(Buffer, 0, MEM_RELEASE);
	return FALSE;
}

BOOL
HCAPI
HcProcessReadNullifiedString(HANDLE hProcess,
	PUNICODE_STRING usStringIn,
	LPWSTR lpStringOut,
	SIZE_T lpSize)
{
	SIZE_T Len;

	/* Get the maximum len we have/can write in given size */
	Len = usStringIn->Length + sizeof(UNICODE_NULL);
	if (lpSize * sizeof(WCHAR) < Len)
	{
		Len = lpSize * sizeof(WCHAR);
	}

	/* Read the string */
	if (!HcProcessReadMemory(hProcess,
		usStringIn->Buffer,
		lpStringOut,
		Len,
		NULL))
	{
		return FALSE;
	}

	/* If we are at the end of the string, prepare to override to nullify string */
	if (Len == usStringIn->Length + sizeof(UNICODE_NULL))
	{
		Len -= sizeof(UNICODE_NULL);
	}

	/* Nullify at the end if needed */
	if (Len >= lpSize * sizeof(WCHAR))
	{
		if (lpSize)
		{
			ASSERT(lpSize >= sizeof(UNICODE_NULL));
			lpStringOut[lpSize - 1] = UNICODE_NULL;
		}
	}
	/* Otherwise, nullify at last writen char */
	else
	{
		ASSERT(Len + sizeof(UNICODE_NULL) <= lpSize * sizeof(WCHAR));
		lpStringOut[Len / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return TRUE;
}

BOOL
HCAPI
HcProcessLdrModuleToHighCallModule(IN HANDLE hProcess,
	IN PLDR_DATA_TABLE_ENTRY Module,
	OUT PHC_MODULE_INFORMATION phcModuleOut)
{
	/* Copy the modules name from the process. */
	if (!HcProcessReadNullifiedString(hProcess,
		&Module->BaseModuleName,
		phcModuleOut->Name,
		Module->BaseModuleName.Length))
	{
		return FALSE;
	}

	/* Copy the module's path from the process. */
	if (!HcProcessReadNullifiedString(hProcess,
		&Module->FullModuleName,
		phcModuleOut->Path,
		Module->FullModuleName.Length))
	{
		return FALSE;
	}

	phcModuleOut->Size = Module->SizeOfImage;
	phcModuleOut->Base = (SIZE_T)Module->ModuleBase;

	return TRUE;
}

BOOL
HCAPI
HcProcessQueryInformationModule(IN HANDLE hProcess,
	IN HMODULE hModule OPTIONAL,
	OUT PHC_MODULE_INFORMATION phcModuleOut)
{
	SIZE_T Count;
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY Module;
	ULONG Len;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	/* If no module was provided, get base as module */
	if (hModule == NULL)
	{
		if (!HcProcessReadMemory(hProcess,
			&(ProcInfo.PebBaseAddress->ImageBaseAddress),
			&hModule,
			sizeof(hModule),
			NULL))
		{
			return FALSE;
		}
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData,
		sizeof(LoaderData),
		NULL))
	{
		return FALSE;
	}

	if (LoaderData == NULL)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	/* Store list head address */
	ListHead = &(LoaderData->InMemoryOrderModuleList);

	/* Read first element in the modules list */
	if (!HcProcessReadMemory(hProcess,
		&(LoaderData->InMemoryOrderModuleList.Flink),
		&ListEntry,
		sizeof(ListEntry),
		NULL))
	{
		return FALSE;
	}

	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
			&Module,
			sizeof(Module),
			NULL))
		{
			return FALSE;
		}

		/* Does that match the module we're looking for? */
		if (Module.ModuleBase == hModule)
		{
			return HcProcessLdrModuleToHighCallModule(hProcess,
				&Module,
				phcModuleOut);
		}

		++Count;
		if (Count > MAX_MODULES)
		{
			break;
		}

		/* Get to next listed module */
		ListEntry = Module.InMemoryOrderLinks.Flink;
	}

	SetLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

BOOL
HCAPI
HcProcessQueryModules(HANDLE hProcess,
	HC_MODULE_CALLBACK_EVENT hcmCallback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY ldrModule;
	PHC_MODULE_INFORMATION Module;
	SIZE_T Count;
	ULONG Len;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(Status);
		return FALSE;
	}

	if (ProcInfo.PebBaseAddress == NULL)
	{
		SetLastError(STATUS_PARTIAL_COPY);
		return FALSE;
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData, sizeof(LoaderData),
		NULL))
	{
		return FALSE;
	}

	/* Store list head address */
	ListHead = &LoaderData->InLoadOrderModuleList;

	/* Read first element in the modules list */
	if (!HcProcessReadMemory(hProcess,
		&(LoaderData->InLoadOrderModuleList.Flink),
		&ListEntry,
		sizeof(ListEntry),
		NULL))
	{
		return FALSE;
	}

	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
			&ldrModule,
			sizeof(ldrModule),
			NULL))
		{
			return FALSE;
		}

		Module = new HC_MODULE_INFORMATION;

		/* Attempt to convert to a HC module */
		if (HcProcessLdrModuleToHighCallModule(hProcess,
			&ldrModule,
			Module))
		{
			/* Give it to the caller */
			if (hcmCallback(*Module, lParam))
			{
				delete Module;
				return TRUE;
			}

			Count += 1;
		}

		delete Module;

		if (Count > MAX_MODULES)
		{
			SetLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}

		/* Get to next listed module */
		ListEntry = ldrModule.InLoadOrderLinks.Flink;
	}

	return FALSE;
}

static ULONG HCAPI HcGetProcessListSize()
{
	NTSTATUS Status;
	ULONG Size = MAXSHORT;
	PSYSTEM_PROCESS_INFORMATION ProcInfoArray;

	/* Loop on it */
	while (TRUE)
	{
		/* Allocate for first test */
		if (!(ProcInfoArray = (PSYSTEM_PROCESS_INFORMATION)
			VirtualAlloc(NULL,
				Size,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE)))
		{
			return FALSE;
		}

		Status = HcQuerySystemInformation(SystemProcessInformation,
			ProcInfoArray,
			Size,
			NULL);

		/* Release, we're only looking for the size. */
		VirtualFree(ProcInfoArray, 0, MEM_RELEASE);

		/* Not enough, go for it again. */
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			Size += MAXSHORT;
			continue;
		}

		break;

	}

	return Size;
}

BOOL
HCAPI
HcQueryProcessesByName(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENT hcpCallback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo;
	HANDLE CurrentHandle;
	PHC_PROCESS_INFORMATION hcpInformation;
	UNICODE_STRING processName;
	PVOID Buffer;
	ULONG Length;

	/* Initialize the unicode string */
	RtlInitUnicodeString(&processName, lpProcessName);

	/* Query the required size. */
	Length = HcGetProcessListSize();

	if (!Length)
	{
		return FALSE;
	}

	/* Allocate the buffer with specified size. */
	if (!(Buffer = VirtualAlloc(NULL,
		Length,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE)))
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		return FALSE;
	}

	processInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	/* Query the process list. */
	if (!NT_SUCCESS(Status = HcQuerySystemInformation(SystemProcessInformation,
		processInfo,
		Length,
		&Length)))
	{
		VirtualFree(Buffer, 0, MEM_RELEASE);
		SetLastError(Status);
		printf("syson %x\n", Status);
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		hcpInformation = new HC_PROCESS_INFORMATION;

		/* Check for a match */
		if (!lpProcessName ||
			RtlEqualUnicodeString(&processInfo->ImageName,
				&processName,
				TRUE))
		{

			hcpInformation->Id = (SIZE_T)processInfo->UniqueProcessId;

			/* Copy the name */
			wcsncpy(hcpInformation->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			/* Try opening the process */
			if ((CurrentHandle = HcProcessOpen((SIZE_T)processInfo->UniqueProcessId,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
			{
				hcpInformation->CanAccess = TRUE;

				/* Query main module */
				HcProcessQueryInformationModule(CurrentHandle,
					NULL,
					&hcpInformation->MainModule);

				HcProcessQueryInformationWindow(CurrentHandle,
					&hcpInformation->MainWindow);

				/* Close this handle. */
				HcCloseHandle(CurrentHandle);
			}

			/* Call the callback as long as the user doesn't return FALSE. */
			if (hcpCallback(*hcpInformation, lParam))
			{
				VirtualFree(Buffer, 0, MEM_RELEASE);
				delete hcpInformation;
				return TRUE;
			}
		}

		delete hcpInformation;

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

	VirtualFree(Buffer, 0, MEM_RELEASE);
	return FALSE;
}

HMODULE
HCAPI
HcLoadLibrary(LPCSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	DWORD Length;
	LPWSTR lpConverted;
	HANDLE hModule;

	if (HcStringIsBad(lpPath))
	{
		return 0;
	}

	if (!(Length = lstrlenA(lpPath)))
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

	if (!MultiByteToWideChar(CP_ACP, 0, lpPath, Length, lpConverted, Length))
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
HcLoadLibrary(LPCWSTR lpPath)
{
	NTSTATUS Status;
	UNICODE_STRING Path;
	HANDLE hModule;

	if (HcStringIsBad(lpPath))
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

static
BOOL BaseCheck(HC_MODULE_INFORMATION hcmInfo, LPARAM lParam)
{
	return hcmInfo.Base > 0;
}

BOOLEAN
HCAPI
HcProcessReady(HANDLE hProcess)
{
	/* Ensure we didn't find it before ntdll was loaded */
	HC_MODULE_INFORMATION hcmInfo;
	if (!HcProcessQueryInformationModule(hProcess, NULL, &hcmInfo))
	{
		return FALSE;
	}
	return hcmInfo.Base > 0;
}

BOOLEAN
HCAPI
HcProcessReady(SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	if (!(hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS)))
	{
		return FALSE;
	}

	/* Ensure we didn't find it before ntdll was loaded */
	Success = HcProcessReady(hProcess);

	HcCloseHandle(hProcess);

	return Success;
}

#pragma region Internal Manual Map Code
static 
SIZE_T
HCAPI MmInternalResolve(PVOID lParam)
{
	PMANUAL_INJECT ManualInject;
	HMODULE hModule;
	SIZE_T Index;
	SIZE_T Function;
	SIZE_T Count;
	SIZE_T Delta;
	PSIZE_T FunctionPointer;
	PWORD ImportList;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)lParam;

	pIBR = ManualInject->BaseRelocation;
	Delta = (SIZE_T)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			ImportList = (PWORD)(pIBR + 1);

			for (Index = 0; Index<Count; Index++)
			{
				if (ImportList[Index])
				{
					FunctionPointer = (PSIZE_T)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (ImportList[Index] & 0xFFF)));
					*FunctionPointer += Delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	/* Manually load all the library imports */
	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		/* Import each */
		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				/* By ordinal */
				Function = (SIZE_T)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				/* By name */
				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (SIZE_T)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

SIZE_T HCAPI MmInternalResolved()
{
	return 0;
}
#pragma endregion

/*
@inprogress
@32bit
*/
BOOLEAN
HCAPI
HcProcessInjectModuleManual(HANDLE hProcess,
	LPCWSTR lpPath)
{
	PIMAGE_DOS_HEADER pHeaderDos;
	PIMAGE_NT_HEADERS pHeaderNt;
	PIMAGE_SECTION_HEADER pHeaderSection;

	HANDLE hThread, hFile;
	PVOID Buffer, ImageBuffer, LoaderBuffer;
	DWORD ExitCode, BytesRead, SectionIndex, FileSize;

	MANUAL_INJECT ManualInject;

	if (!hProcess)
	{
		return FALSE;
	}

	if (!HcProcessReady(hProcess))
	{
		SetLastError(STATUS_PENDING);
		return FALSE;
	}

	hFile = CreateFileW(lpPath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	FileSize = GetFileSize(hFile, NULL);

	Buffer = VirtualAlloc(NULL,
		FileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!Buffer)
	{
		SetLastError(STATUS_INSUFFICIENT_RESOURCES);
		HcCloseHandle(hFile);
		return FALSE;
	}

	if (!ReadFile(hFile,
		Buffer,
		FileSize,
		&BytesRead,
		NULL) || BytesRead != FileSize)
	{
		SetLastError(STATUS_FAILED);
		VirtualFree(Buffer, 0, MEM_RELEASE);
		HcCloseHandle(hFile);

		return FALSE;
	}

	HcCloseHandle(hFile);

	pHeaderDos = (PIMAGE_DOS_HEADER)Buffer;

	if (pHeaderDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		SetLastError(STATUS_INVALID_HANDLE);
		VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

	pHeaderNt = (PIMAGE_NT_HEADERS)((LPBYTE)Buffer + pHeaderDos->e_lfanew);

	if (pHeaderNt->Signature != IMAGE_NT_SIGNATURE)
	{
		SetLastError(STATUS_INVALID_HANDLE);
		VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

	if (!(pHeaderNt->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		SetLastError(STATUS_INVALID_PARAMETER);

		VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

	ImageBuffer = HcProcessAllocate(hProcess,
		NULL,
		pHeaderNt->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!ImageBuffer)
	{
		VirtualFree(Buffer, 0, MEM_RELEASE);

		return FALSE;
	}

	SIZE_T written;

	if (!HcProcessWriteMemory(hProcess,
		ImageBuffer,
		Buffer,
		pHeaderNt->OptionalHeader.SizeOfHeaders,
		&written))
	{
		HcProcessFree(hProcess, ImageBuffer, 0, MEM_RELEASE);
		VirtualFree(Buffer, 0, MEM_RELEASE);

		return FALSE;
	}

	pHeaderSection = (PIMAGE_SECTION_HEADER)(pHeaderNt + 1);

	for (SectionIndex = 0; SectionIndex < pHeaderNt->FileHeader.NumberOfSections; SectionIndex++)
	{
		HcProcessWriteMemory(hProcess,
			(PVOID)((LPBYTE)ImageBuffer + pHeaderSection[SectionIndex].VirtualAddress),
			(PVOID)((LPBYTE)Buffer + pHeaderSection[SectionIndex].PointerToRawData),
			pHeaderSection[SectionIndex].SizeOfRawData,
			NULL);
	}

	LoaderBuffer = HcProcessAllocate(hProcess,
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!LoaderBuffer)
	{
		HcProcessFree(hProcess, ImageBuffer, 0, MEM_RELEASE);
		VirtualFree(Buffer, 0, MEM_RELEASE);

		return FALSE;
	}

	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

	ManualInject.ImageBase = ImageBuffer;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ImageBuffer + pHeaderDos->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	/* This is used inside of the target executable */
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;

	/* Write loader information */
	if (!HcProcessWriteMemory(hProcess,
		LoaderBuffer,
		&ManualInject,
		sizeof(MANUAL_INJECT),
		NULL))
	{
		return FALSE;
	}

	/* Write loader code */
	if (!HcProcessWriteMemory(hProcess,
		(PVOID)((PMANUAL_INJECT)LoaderBuffer + 1),
		MmInternalResolve,
		(ULONG)((SIZE_T)MmInternalResolved - (SIZE_T)MmInternalResolve),
		NULL))
	{
		return FALSE;
	}

	/* Create a thread specifically for this dll, this will execute the code remotely */
	hThread = HcCreateRemoteThread(hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)LoaderBuffer + 1),
		LoaderBuffer,
		0,
		NULL);

	if (!hThread)
	{
		HcProcessFree(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcProcessFree(hProcess, ImageBuffer, 0, MEM_RELEASE);

		VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &ExitCode);

	if (!ExitCode)
	{
		HcProcessFree(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcProcessFree(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcCloseHandle(hThread);

		VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

	HcCloseHandle(hThread);
	HcProcessFree(hProcess, LoaderBuffer, 0, MEM_RELEASE);

	VirtualFree(Buffer, 0, MEM_RELEASE);
	return TRUE;
}

BOOLEAN 
HCAPI
HcProcessSuspend(HANDLE hProcess)
{
	if (!hProcess)
	{
		return FALSE;
	}

	return NT_SUCCESS(HcSuspendProcess(hProcess));
}

BOOLEAN 
HCAPI 
HcProcessSuspend(SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	if (!hProcess)
	{
		return FALSE;
	}

	Status = HcSuspendProcess(hProcess);

	HcCloseHandle(hProcess);
	return NT_SUCCESS(Status);
}

BOOLEAN 
HCAPI 
HcProcessResume(HANDLE hProcess)
{
	if (!hProcess)
	{
		return FALSE;
	}

	return NT_SUCCESS(HcResumeProcess(hProcess));
}

BOOLEAN
HCAPI 
HcProcessResume(SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	if (!hProcess)
	{
		return FALSE;
	}

	Status = HcResumeProcess(hProcess);

	HcCloseHandle(hProcess);
	return NT_SUCCESS(Status);
}

mem_result
HCAPI 
HcInternalMemoryTest(SIZE_T dwBaseAddress,
	SIZE_T dwBufferLength)
{
	mem_result _result = { 0 };
	_result.address = dwBaseAddress;
	_result.length = dwBufferLength;
	_result.buffer = (unsigned char*)malloc(dwBufferLength);
	_result.accessible = true;

	if (!dwBaseAddress)
	{
		_result.accessible = false;
	}

	__try
	{
		/* try reading each piece of memory specified */
		for (SIZE_T i = 0; i < dwBufferLength; i++)
		{
			_result.buffer[i] = (unsigned char)(dwBaseAddress + i);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* we hit an inaccessible memory region */
		_result.accessible = false;

		/* return immedietly */
		return _result;
	}

	return _result;
}

mem_result
HCAPI
HcInternalMemoryTest(SIZE_T dwBaseAddress,
	SIZE_T* pdwOffsets,
	SIZE_T dwOffsetCount,
	SIZE_T dwBufferLength)
{
	mem_result _result = { 0 };
	_result.address = dwBaseAddress;
	_result.length = dwBufferLength;
	_result.buffer = (unsigned char*)malloc(dwBufferLength);
	_result.accessible = true;

	if (!dwBaseAddress)
	{
		_result.accessible = false;
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

		for (SIZE_T i = 0; i < dwBufferLength; i++)
		{
			/* read the end pointer with the specified buffer length */
			_result.buffer[i] = (unsigned char)(_result.address + i);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* we hit inacessible memory */
		_result.accessible = false;
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
HcInternalReadString(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount)
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
HcInternalReadInt(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount)
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

int
HCAPI
HcInternalReadInt(SIZE_T baseAddress)
{
	return (int)*(SIZE_T*)baseAddress;
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

	return (SIZE_T) address + offsets[offsetCount - 1];
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
HcInternalPatternFind(const char* pattern, const char* mask, HC_MODULE_INFORMATION module)
{
	/* specifies where the function will start searching from */
	SIZE_T base = module.Base;

	/* specifies where the function will end searching */
	SIZE_T size = module.Size;

	/* loop through the specified module */
	for (SIZE_T retAddress = base; retAddress < base + size - strlen(mask); retAddress++)
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

LPSTR 
HCAPI
HcPathMainModule()
{
	char* buffer = (char*)malloc(MAX_PATH);
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	return buffer;
}

LPSTR 
HCAPI
HcPathLocalDirectory()
{
	char* module = HcPathMainModule();
	SIZE_T index = HcStringCharIndex(module, '\\');
	char* retn = (char*)malloc(MAX_PATH);
	HcStringSubtract(module, retn, 0, index);
	free(module);
	return index != -1 ? retn : (char*)0;
}

#ifdef PROGRAM_ALIAS
LPSTR 
HCAPI 
HcPathLogFile()
{
	char* buffer = (char*)malloc(MAX_PATH);
	char* path = HcPathLocalDirectory();
	sprintf(buffer, "%s%s.log", path, PROGRAM_ALIAS);
	free(path);
	return buffer;
}

LPSTR 
HCAPI 
HcPathConfigFile()
{
	char* buffer = (char*)malloc(MAX_PATH);
	char* path = HcPathLocalDirectory();
	sprintf(buffer, "%s%s.config", path, PROGRAM_ALIAS);
	free(path);
	return buffer;
}
#endif

BOOLEAN 
HCAPI 
HcPathFileExists(LPCSTR name)
{
	return (GetFileAttributesA(name) != 0xFFFFFFFF);
}

BOOLEAN 
HCAPI 
HcPathFileExists(LPCWSTR name)
{
	return (GetFileAttributesW(name) != 0xFFFFFFFF);
}

SIZE_T 
HCAPI 
HcPathFileSize(LPCSTR lpPath)
{
	SIZE_T FileSize;
	HANDLE hFile;

	if (!(hFile = CreateFileA(lpPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL)))
	{
		return 0;
	}

	FileSize = GetFileSize(hFile, NULL);

	/* Close handle and return */
	HcCloseHandle(hFile);
	return FileSize;
}

#ifdef PROGRAM_ALIAS

VOID 
HCAPI 
HcPathLogNormal(const char* input, ...)
{
	char* path = HcPathLogFile();
	FILE* iobuf = fopen(path, "ab+");
	free(path);

	if (iobuf)
	{
		/* format the string */
		char out[256];
		va_list args;
		va_start(args, input);
		vsnprintf(out, 256, input, args);
		va_end(args);

		/* get the current time in string format */
		const char* time = HcStringTime();
		fprintf(iobuf, "%s [%d] %s::Normal: %s\n", time, GetCurrentThreadId(), PROGRAM_ALIAS, out);
		fclose(iobuf);
	}
	else
	{
		FILE* logbuf = fopen("LOGFAILURE", "ab+");
		fprintf(logbuf, "Failed to open and create log file buffer! Last message: %s", input);
		fclose(logbuf);
	}
}

VOID 
HCAPI 
HcPathLogError(const char* input, ...)
{
	char* path = HcPathLogFile();
	FILE* iobuf = fopen(path, "ab+");
	free(path);

	if (iobuf)
	{
		/* format the string */
		char out[256];
		va_list args;
		va_start(args, input);
		vsnprintf(out, 256, input, args);
		va_end(args);

		/* get the current time in string format */
		const char* time = HcStringTime();

		fprintf(iobuf, "!--ERROR--%s [%d] %s::Error: %s\n", time, GetCurrentThreadId(), PROGRAM_ALIAS, out);
		fclose(iobuf);
	}
	else
	{
		FILE* logbuf = fopen("LOGFAILURE", "ab+");
		fprintf(logbuf, "Failed to open and create log file buffer! Last message: %s", input);
		fclose(logbuf);
	}
}
#endif

#pragma endregion
