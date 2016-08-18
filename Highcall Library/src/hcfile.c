#include "../include/hcfile.h"
#include "../include/hcstring.h"
#include "../include/hcsyscall.h"
#include "../include/hcprocess.h"
#include "../include/hcmodule.h"

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

#ifdef PROGRAM_ALIAS
LPSTR
HCAPI
HcFileLogFile()
{
	char* buffer = (char*)malloc(MAX_PATH);
	char* path = HcFileLocalDirectory();
	sprintf(buffer, "%s%s.log", path, PROGRAM_ALIAS);
	free(path);
	return buffer;
}

LPSTR
HCAPI
HcFileConfigFile()
{
	char* buffer = (char*)malloc(MAX_PATH);
	char* path = HcFileLocalDirectory();
	sprintf(buffer, "%s%s.config", path, PROGRAM_ALIAS);
	free(path);
	return buffer;
}
#endif

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

#ifdef PROGRAM_ALIAS

VOID
HCAPI
HcFileLogNormal(const char* input, ...)
{
	char* path = HcFileLogFile();
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
HcFileLogError(const char* input, ...)
{
	char* path = HcFileLogFile();
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


/*
@implemented
*/
DWORD
HCAPI
HcFileRvaOffset(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA)
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
				return (DWORD)RVA;
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
HcFileOffsetByExportNameA(HMODULE hModule, LPCSTR lpExportName)
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

	szExportVA = (SIZE_T)HcModuleProcedureAddressA(hModule, lpExportName);
	if (szExportVA)
	{
		/* Calculate the relative offset */
		szExportRVA = szExportVA - szModule;

		return HcFileRvaOffset(pHeaderNT, szExportRVA);
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

	dwExportVA = (SIZE_T)HcModuleProcedureAddressW(hModule, lpExportName);
	if (dwExportVA)
	{
		/* Calculate the relative offset */
		dwExportRVA = dwExportVA - dwModule;

		return HcFileRvaOffset(pHeaderNT, dwExportRVA);
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

	if (!(dwFileOffset = HcFileOffsetByExportNameA(hModule, lpExportName)))
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
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
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
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		return 0;
	}

	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

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
	if (!lpModulePath)
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
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
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		return 0;
	}

	if (!(SetFilePointer(hFile, dwFileOffset, 0, FILE_BEGIN)))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	if (!ReadFile(hFile, lpBuffer, dwCount, &BytesRead, NULL))
	{
		VirtualFree(lpModulePath, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	VirtualFree(lpModulePath, 0, MEM_RELEASE);
	CloseHandle(hFile);
	return BytesRead;
}

DWORD
HCAPI
HcFileOffsetByVirtualAddress(LPBYTE lpBaseAddress)
{
	PIMAGE_DOS_HEADER pHeaderDOS;
	PIMAGE_NT_HEADERS pHeaderNT;
	SIZE_T dwRVA;
	SIZE_T dwModule;
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
	dwRVA = ((SIZE_T)lpBaseAddress) - dwModule;

	return HcFileRvaOffset(pHeaderNT, dwRVA);
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