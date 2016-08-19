#include "../include/hcfile.h"
#include "../include/hcstring.h"
#include "../include/hcsyscall.h"
#include "../include/hcprocess.h"
#include "../include/hcmodule.h"
#include "../include/hcpe.h"

LPSTR
HCAPI
HcFileMainModule()
{
	char* buffer = (char*)malloc(MAX_PATH);
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	return buffer;
}

LPSTR
HCAPI
HcFileLocalDirectory()
{
	char* module = HcFileMainModule();
	SIZE_T index = HcStringCharIndex(module, '\\');
	char* retn = (char*)malloc(MAX_PATH);
	HcStringSubtract(module, retn, 0, index, MAX_PATH);
	free(module);
	return index != -1 ? retn : (char*)0;
}

BOOLEAN
HCAPI
HcFileExistsA(LPCSTR name)
{
	return (GetFileAttributesA(name) != 0xFFFFFFFF);
}

BOOLEAN
HCAPI
HcFileExistsW(LPCWSTR name)
{
	return (GetFileAttributesW(name) != 0xFFFFFFFF);
}

SIZE_T
HCAPI
HcFileSize(LPCSTR lpPath)
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
	HcClose(hFile);
	return FileSize;
}

BOOLEAN
HCAPI
HcFileQueryInformationW(LPCWSTR lpPath, PHC_FILE_INFORMATION fileInformation)
{
	HANDLE hFile;
	DWORD BytesRead;

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

	fileInformation->Size = GetFileSize(hFile, NULL);

	fileInformation->Data = (PBYTE)VirtualAlloc(NULL,
		fileInformation->Size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!ReadFile(hFile,
		fileInformation->Data,
		fileInformation->Size,
		&BytesRead,
		NULL) || BytesRead != fileInformation->Size)
	{
		SetLastError(STATUS_FAILED);
		VirtualFree(fileInformation->Data, 0, MEM_RELEASE);
		HcClose(hFile);

		return FALSE;
	}

	HcClose(hFile);

	return TRUE;
}

BOOLEAN
HCAPI
HcFileQueryInformationA(LPCSTR lpPath, PHC_FILE_INFORMATION fileInformation)
{
	HANDLE hFile;
	DWORD BytesRead;

	hFile = CreateFileA(lpPath,
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

	fileInformation->Size = GetFileSize(hFile, NULL);

	fileInformation->Data = (PBYTE)VirtualAlloc(NULL,
		fileInformation->Size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!ReadFile(hFile,
		fileInformation->Data,
		fileInformation->Size,
		&BytesRead,
		NULL) || BytesRead != fileInformation->Size)
	{
		SetLastError(STATUS_FAILED);
		VirtualFree(fileInformation->Data, 0, MEM_RELEASE);
		HcClose(hFile);

		return FALSE;
	}

	HcClose(hFile);

	return TRUE;
}

/*
@implemented
*/
DWORD
HCAPI
HcFileOffsetByExportNameA(HMODULE hModule, LPCSTR lpExportName)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T szExportRVA;
	SIZE_T szExportVA;
	SIZE_T szModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}
	szModule = (SIZE_T)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	szExportVA = (SIZE_T)HcModuleProcedureAddressA(hModule, lpExportName);
	if (szExportVA)
	{
		/* Calculate the relative offset */
		szExportRVA = szExportVA - szModule;

		return HcPEGetRawFromRva(pHeaderNT, szExportRVA);
	}

	return 0;
}

/*
@implemented
*/
DWORD
HCAPI
HcFileOffsetByExportNameW(HMODULE hModule, LPCWSTR lpExportName)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T dwExportRVA;
	SIZE_T dwExportVA;
	SIZE_T dwModule;

	if (!hModule)
	{
		hModule = ((HMODULE)NtCurrentPeb()->ImageBaseAddress);
	}

	dwModule = (SIZE_T)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	dwExportVA = (SIZE_T)HcModuleProcedureAddressW(hModule, lpExportName);
	if (dwExportVA)
	{
		/* Calculate the relative offset */
		dwExportRVA = dwExportVA - dwModule;

		return HcPEGetRawFromRva(pHeaderNT, dwExportRVA);
	}

	return 0;
}

/*
@implemented
@problem: can't call the native handle close.
*/
SIZE_T
HCAPI
HcFileReadModuleA(HMODULE hModule, LPCSTR lpExportName, BYTE* lpBuffer, DWORD dwCount)
{
	DWORD dwFileOffset;
	LPSTR lpModulePath;
	HANDLE hFile;
	DWORD BytesRead;

	dwFileOffset = HcFileOffsetByExportNameA(hModule, lpExportName);
	if (!dwFileOffset)
	{
		return 0;
	}

	lpModulePath = (LPSTR)VirtualAlloc(NULL,
		MAX_PATH,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	if (!lpModulePath)
	{
		return 0;
	}

	/* Acquire path of targetted module. */
	GetModuleFileNameA(hModule, lpModulePath, MAX_PATH);

	/* Open it up */
	if (!(hFile = CreateFileA(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		return 0;
	}

	/* Run to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	/* Snatch the data */
	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	/* Fuck off */
	VirtualFree(lpModulePath, 0, MEM_RELEASE);
	CloseHandle(hFile);
	return BytesRead;
}

/*
@implemented
@problem: can't call the native handle close.
*/
SIZE_T
HCAPI
HcFileReadModuleW(HMODULE hModule, LPCWSTR lpExportName, BYTE* lpBuffer, DWORD dwCount)
{
	DWORD dwFileOffset;
	LPWSTR lpModulePath;
	HANDLE hFile;
	DWORD BytesRead;

	if (!(dwFileOffset = HcFileOffsetByExportNameW(hModule, lpExportName)))
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

	/* Open it up */
	if (!(hFile = CreateFileW(lpModulePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		return 0;
	}

	/* Run to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	/* Snatch the data */
	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	/* Fuck off */
	VirtualFree(lpModulePath, 0, MEM_RELEASE);
	CloseHandle(hFile);
	return BytesRead;
}

DWORD
HCAPI
HcFileOffsetByVirtualAddress(LPBYTE lpBaseAddress)
{
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T szRva;
	SIZE_T szModule;
	MEMORY_BASIC_INFORMATION memInfo;
	HMODULE hModule;

	/* Find the module that allocated the address */
	if (!HcProcessVirtualQuery(NtCurrentProcess,
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

	szModule = (SIZE_T)hModule;

	pHeaderNT = HcPEGetNtHeader(hModule);
	if (!pHeaderNT)
	{
		return 0;
	}

	/* Calculate the relative offset */
	szRva = ((SIZE_T)lpBaseAddress) - szModule;

	return HcPEGetRawFromRva(pHeaderNT, szRva);
}

SIZE_T
HCAPI
HcFileReadAddress(LPBYTE lpBaseAddress, PBYTE lpBufferOut, DWORD dwCountToRead)
{
	DWORD dwFileOffset;
	LPWSTR lpModulePath;
	HANDLE hFile;
	DWORD BytesRead;
	HMODULE hModule;
	MEMORY_BASIC_INFORMATION memInfo;

	/* Find the module that allocated the address */
	if (!HcProcessVirtualQuery(NtCurrentProcess,
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
	dwFileOffset = HcFileOffsetByVirtualAddress(lpBaseAddress);
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
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
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
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		return 0;
	}

	/* Go to the offset */
	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		HcClose(hFile);
		return 0;
	}

	/* Read it */
	if (!ReadFile(hFile, lpBufferOut, dwCountToRead, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		HcClose(hFile);
		return 0;
	}

	VirtualFree(lpModulePath, 0, MEM_RELEASE);
	HcClose(hFile);
	return BytesRead;
}