#pragma once
#include <windows.h>
#include "ntdef.h"
#include "nttype.h"
#include "hctype.h"

extern HMODULE NTDLL;
extern HMODULE USER32;
extern HMODULE KERNEL32;

NTSTATUS
HCAPI
HcGetTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated
);

HMODULE
HCAPI
HcGetModuleHandle(LPCWSTR lpModuleName);

HMODULE
HCAPI
HcGetModuleHandle(LPCSTR lpModuleName);

DWORD
HCAPI
HcGetProcedureAddress(HANDLE hModule, LPCSTR lpProcedureName);

DWORD
HCAPI
HcGetProcedureAddress(HANDLE hModule, LPCWSTR lpProcedureName);

SyscallIndex
HCAPI
HcSyscallIndex(LPCSTR lpName);

SyscallIndex
HCAPI
HcSyscallIndex(LPCWSTR lpName);

VOID
HCAPI
HcCloseHandle(HANDLE hObject);

DWORD
HCAPI
HcSyscallForwardPtr();

BOOL
HCAPI
HcStringIsBad(LPCSTR lpcStr);

BOOL
HCAPI
HcStringIsBad(LPCWSTR lpcStr);

LPSTR*
HCAPI
HcStringSplit(LPSTR lpStr, const char cDelimiter, PDWORD pdwCount);

VOID
HCAPI
HcStringSplitToIntArray(LPSTR lpStr, const char delim, int* pArray, PDWORD dwCount);

VOID
HCAPI
HcStringIntToStringArray(int pIntArray[], DWORD dwCountToRead, LPSTR* lpOutStringArray);

VOID
HCAPI
HcStringSubtract(LPCSTR lpStr, LPSTR lpOutStr, DWORD dwIndex, DWORD dwEndIndex, size_t lpSize = 256);

DWORD
HCAPI
HcStringCharIndex(LPCSTR lpStr, char delim);

LPCSTR
HCAPI
HcStringTime();

VOID
HCAPI
HcStringToLower(LPSTR lpStr);

VOID
HCAPI
HcStringToLower(LPWSTR lpStr);

VOID
HCAPI
HcStringToUpper(LPSTR lpStr);

VOID
HCAPI
HcStringToUpper(LPWSTR lpStr);

BOOL
HCAPI
HcStringEqual(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);

BOOL
HCAPI
HcStringEqual(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);

DWORD
HCAPI
HcRVAToFileOffset(PIMAGE_NT_HEADERS pImageHeader, DWORD RVA);

DWORD
HCAPI
HcExportToFileOffset(HMODULE hModule, LPCSTR lpExportName);

DWORD
HCAPI
HcExportToFileOffset(HMODULE hModule, LPCWSTR lpExportName);

size_t
HCAPI
HcReadFileModule(HMODULE hModule, LPCSTR lpExportName, BYTE* lpBuffer, size_t t_Count);

size_t
HCAPI
HcReadFileModule(HMODULE hModule, LPCWSTR lpExportName, BYTE* lpBuffer, size_t t_Count);

DWORD
HCAPI
HcSyscallForwardPtr();

HANDLE
HCAPI
HcProcessOpen(DWORD dwProcessId, ACCESS_MASK DesiredAccess);

BOOL
HCAPI
HcProcessFree(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD dwFreeType);

LPVOID
HCAPI
HcProcessAllocate(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flAllocationType,
	IN DWORD flProtect);

BOOL
HCAPI
HcProcessWriteMemory(HANDLE hProcess,
	PVOID lpBaseAddress,
	CONST VOID* lpBuffer,
	SIZE_T nSize,
	PSIZE_T lpNumberOfBytesWritten);

BOOL
HCAPI
HcProcessReadMemory(IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesRead);

BOOL
HCAPI
HcProcessQueryInformationWindow(_In_ HANDLE ProcessHandle,
	PHC_WINDOW_INFORMATION HCWindowInformation);

BOOL
HCAPI
HcProcessReadNullifiedString(HANDLE hProcess,
	PUNICODE_STRING usStringIn,
	LPWSTR lpStringOut,
	SIZE_T lpSize);

BOOL
HCAPI
HcProcessLdrModuleToHighCallModule(IN HANDLE hProcess,
	IN PLDR_DATA_TABLE_ENTRY Module,
	OUT PHC_MODULE_INFORMATION phcModuleOut);

BOOL
HCAPI
HcProcessQueryInformationModule(IN HANDLE hProcess,
	IN HMODULE hModule OPTIONAL,
	OUT PHC_MODULE_INFORMATION phcModuleOut);

BOOL
HCAPI
HcProcessQueryModules(HANDLE hProcess,
	HC_MODULE_CALLBACK_EVENT hcmCallback,
	LPARAM lParam);

SIZE_T
HCAPI
HcGetProcessListSize();

BOOL
HCAPI
HcQueryProcessesByName(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENT hcpCallback,
	LPARAM lParam);

HMODULE
HCAPI
HcLoadLibrary(LPCSTR lpPath);

HMODULE
HCAPI
HcLoadLibrary(LPCWSTR lpPath);

BOOLEAN
HCAPI
HcProcessReady(HANDLE hProcess);

BOOLEAN
HCAPI
HcProcessReady(DWORD dwProcessId);

BOOLEAN
HCAPI
HcProcessInjectModuleManual(HANDLE hProcess,
	LPCWSTR lpPath);

BOOLEAN
HCAPI
HcProcessSuspend(HANDLE hProcess);

BOOLEAN
HCAPI
HcProcessSuspend(DWORD dwProcessId);

BOOLEAN
HCAPI
HcProcessResume(HANDLE hProcess);

BOOLEAN
HCAPI
HcProcessResume(DWORD dwProcessId);

mem_result
HCAPI
HcInternalMemoryTest(DWORD dwBaseAddress, DWORD dwBufferLength);

mem_result
HCAPI
HcInternalMemoryTest(DWORD dwBaseAddress, DWORD* pdwOffsets, DWORD dwOffsetCount, DWORD dwBufferLength);

LPCSTR
HCAPI
HcInternalReadString(DWORD memAddress, unsigned int* ptrOffsets, unsigned int offsetCount);

LPCSTR
HCAPI
HcInternalReadString(DWORD memAddress);

int
HCAPI
HcInternalReadInt(DWORD memAddress, unsigned int* ptrOffsets, unsigned int offsetCount);

int
HCAPI
HcInternalReadInt(DWORD baseAddress);

DWORD
HCAPI
HcInternalLocatePointer(DWORD baseAddress, DWORD* offsets, unsigned int offsetCount);

VOID
HCAPI
HcInternalMemoryWrite(PVOID pAddress, DWORD dwLen, BYTE* ptrWrite);

VOID
HCAPI
HcInternalMemoryNop(PVOID pAddress, DWORD dwLen);

DWORD
HCAPI
HcInternalPatternFind(const char* pattern, const char* mask, HC_MODULE_INFORMATION module);

BOOLEAN
HCAPI
HcInternalMainModule(PHC_MODULE_INFORMATION hcmInfo);

LPSTR
HCAPI
HcPathMainModule();

LPSTR
HCAPI
HcPathLocalDirectory();

#ifdef PROGRAM_ALIAS

LPSTR
HCAPI
HcPathLogFile();

LPSTR
HCAPI
HcPathConfigFile();

VOID
HCAPI
HcPathLogNormal(const char* input, ...);

VOID
HCAPI
HcPathLogError(const char* input, ...);

#endif

BOOLEAN
HCAPI
HcPathFileExists(LPCSTR name);

BOOLEAN
HCAPI
HcPathFileExists(LPCWSTR name);

SIZE_T
HCAPI
HcPathFileSize(LPCSTR lpPath);

