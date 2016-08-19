#ifndef HC_FILE_H
#define HC_FILE_H

#include "../include/hcdef.h"
#include "../native/native.h"

#if defined (__cplusplus)
extern "C" {
#endif

	LPSTR
		HCAPI
		HcFileMainModule();

	LPSTR
		HCAPI
		HcFileLocalDirectory();

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