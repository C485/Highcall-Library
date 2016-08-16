#ifndef HC_FILE_H
#define HC_FILE_H

#include "hcdef.h"
#include "native.h"

#if defined (__cplusplus)
extern "C" {
#endif

	LPSTR
		HCAPI
		HcFileMainModule();

	LPSTR
		HCAPI
		HcFileLocalDirectory();

#ifdef PROGRAM_ALIAS

	LPSTR
		HCAPI
		HcFileLogFile();

	LPSTR
		HCAPI
		HcFileConfigFile();

	VOID
		HCAPI
		HcFileLogNormal(const char* input, ...);

	VOID
		HCAPI
		HcFileLogError(const char* input, ...);

#endif

	BOOLEAN
		HCAPI
		HcFileExistsA(LPCSTR name);

	BOOLEAN
		HCAPI
		HcFileExistsW(LPCWSTR name);

	SIZE_T
		HCAPI
		HcFileSize(LPCSTR lpPath);

	BOOLEAN
		HCAPI
		HcFileQueryInformationW(LPCWSTR lpPath, PHC_FILE_INFORMATION fileInformation);

	BOOLEAN
		HCAPI
		HcFileQueryInformationA(LPCSTR lpPath, PHC_FILE_INFORMATION fileInformation);

	DWORD
		HCAPI
		HcFileRvaOffset(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA);

	DWORD
		HCAPI
		HcFileOffsetByExportNameA(HMODULE hModule, LPCSTR lpExportName);

	DWORD
		HCAPI
		HcFileOffsetByExportNameW(HMODULE hModule, LPCWSTR lpExportName);

	DWORD
		HCAPI
		HcFileOffsetByVirtualAddress(LPBYTE lpBaseAddress);

	SIZE_T
		HCAPI
		HcFileReadModuleA(HMODULE hModule, LPCSTR lpExportName, BYTE* lpBuffer, DWORD dwCount);

	SIZE_T
		HCAPI
		HcFileReadModuleW(HMODULE hModule, LPCWSTR lpExportName, BYTE* lpBuffer, DWORD dwCount);

	SIZE_T
		HCAPI
		HcFileReadAddress(LPBYTE lpBaseAddress, PBYTE lpBufferOut, DWORD dwCountToRead);

#endif

#if defined (__cplusplus)
}
#endif