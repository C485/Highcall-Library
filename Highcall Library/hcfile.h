#pragma once
#include "hcdef.h"
#include "native.h"

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
HcFileExists(LPCSTR name);

BOOLEAN
HCAPI
HcFileExists(LPCWSTR name);

SIZE_T
HCAPI
HcFileSize(LPCSTR lpPath);

BOOLEAN
HCAPI
HcFileQueryInformation(LPCWSTR lpPath, PHC_FILE_INFORMATION fileInformation);

BOOLEAN
HCAPI
HcFileQueryInformation(LPCSTR lpPath, PHC_FILE_INFORMATION fileInformation);

DWORD
HCAPI
HcFileRvaOffset(PIMAGE_NT_HEADERS pImageHeader, SIZE_T RVA);

DWORD
HCAPI
HcFileOffsetByExportName(HMODULE hModule, LPCSTR lpExportName);

DWORD
HCAPI
HcFileOffsetByExportName(HMODULE hModule, LPCWSTR lpExportName);

DWORD
HCAPI
HcFileOffsetByVirtualAddress(LPBYTE lpBaseAddress);

SIZE_T
HCAPI
HcFileReadModule(HMODULE hModule, LPCSTR lpExportName, BYTE* lpBuffer, DWORD dwCount);

SIZE_T
HCAPI
HcFileReadModule(HMODULE hModule, LPCWSTR lpExportName, BYTE* lpBuffer, DWORD dwCount);

SIZE_T
HCAPI
HcFileReadAddress(LPBYTE lpBaseAddress, PBYTE lpBufferOut, DWORD dwCountToRead);