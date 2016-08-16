#pragma once
#include "native.h"
#include "hcdef.h"

BOOLEAN
HCAPI
HcProcessExitCode(IN SIZE_T dwProcessId,
	IN LPDWORD lpExitCode);

BOOLEAN
HCAPI
HcProcessExitCode(IN HANDLE hProcess,
	IN LPDWORD lpExitCode);

HANDLE
HCAPI
HcProcessOpen(SIZE_T dwProcessId, ACCESS_MASK DesiredAccess);

BOOL
HCAPI
HcProcessFree(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN ULONG dwFreeType);

LPVOID
HCAPI
HcProcessAllocate(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN ULONG flAllocationType,
	IN ULONG flProtect);

BOOL
HCAPI
HcProcessWriteMemory(HANDLE hProcess,
	LPVOID lpBaseAddress,
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

SIZE_T
NTAPI
HcProcessVirtualQuery(IN HANDLE hProcess,
	IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	IN SIZE_T dwLength);

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
HcProcessEnumModules(HANDLE hProcess,
	HC_MODULE_CALLBACK_EVENT hcmCallback,
	LPARAM lParam);

VOID
HCAPI
HcProcessStealthEnumModules(
	_In_ HANDLE ProcessHandle,
	HC_MODULE_CALLBACK_EVENT hcmCallback,
	LPARAM lParam);

BOOLEAN
HCAPI
HcProcessReady(HANDLE hProcess);

BOOLEAN
HCAPI
HcProcessReady(SIZE_T dwProcessId);

BOOLEAN
HCAPI
HcProcessInjectModuleManual(HANDLE hProcess,
	LPCWSTR lpPath);

BOOLEAN
HCAPI
HcProcessSuspend(HANDLE hProcess);

BOOLEAN
HCAPI
HcProcessSuspend(SIZE_T dwProcessId);

BOOLEAN
HCAPI
HcProcessResume(HANDLE hProcess);

BOOLEAN
HCAPI
HcProcessResume(SIZE_T dwProcessId);

SIZE_T
WINAPI
HcProcessModuleFileName(HANDLE hProcess,
	LPVOID lpv,
	LPWSTR lpFilename,
	DWORD nSize);

BOOL
HCAPI
HcProcessQueryByName(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENT hcpCallback,
	LPARAM lParam);