#ifndef HC_PROCESS_H
#define HC_PROCESS_H

#include "../native/native.h"
#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	BOOLEAN
		HCAPI
		HcProcessExitCode(IN SIZE_T dwProcessId,
			IN LPDWORD lpExitCode);

	BOOLEAN
		HCAPI
		HcProcessExitCodeEx(IN HANDLE hProcess,
			IN LPDWORD lpExitCode);

	HANDLE
		HCAPI
		HcProcessOpen(SIZE_T dwProcessId, ACCESS_MASK DesiredAccess);

	BOOLEAN
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

	BOOLEAN
		HCAPI
		HcProcessWriteMemory(HANDLE hProcess,
			LPVOID lpBaseAddress,
			CONST VOID* lpBuffer,
			SIZE_T nSize,
			PSIZE_T lpNumberOfBytesWritten);

	BOOLEAN
		HCAPI
		HcProcessReadMemory(IN HANDLE hProcess,
			IN LPCVOID lpBaseAddress,
			IN LPVOID lpBuffer,
			IN SIZE_T nSize,
			OUT SIZE_T* lpNumberOfBytesRead);

	HANDLE
		HCAPI
		HcProcessCreateThread(IN HANDLE hProcess,
			IN LPTHREAD_START_ROUTINE lpStartAddress,
			IN LPVOID lpParamater,
			IN DWORD dwCreationFlags);

	SIZE_T
		NTAPI
		HcProcessVirtualQuery(IN HANDLE hProcess,
			IN LPCVOID lpAddress,
			OUT PMEMORY_BASIC_INFORMATION lpBuffer,
			IN SIZE_T dwLength);

	BOOLEAN
		HCAPI
		HcProcessQueryInformationWindow(_In_ HANDLE ProcessHandle,
			PHC_WINDOW_INFORMATION HCWindowInformation);

	BOOLEAN
		HCAPI
		HcProcessReadNullifiedString(HANDLE hProcess,
			PUNICODE_STRING usStringIn,
			LPWSTR lpStringOut,
			SIZE_T lpSize);

	BOOLEAN
		HCAPI
		HcProcessLdrModuleToHighCallModule(IN HANDLE hProcess,
			IN PLDR_DATA_TABLE_ENTRY Module,
			OUT PHC_MODULE_INFORMATION phcModuleOut);

	BOOLEAN
		HCAPI
		HcProcessQueryInformationModule(IN HANDLE hProcess,
			IN HMODULE hModule OPTIONAL,
			OUT PHC_MODULE_INFORMATION phcModuleOut);

	BOOLEAN
		HCAPI
		HcProcessEnumModules(HANDLE hProcess,
			HC_MODULE_CALLBACK_EVENT hcmCallback,
			LPARAM lParam);

	BOOLEAN
		HCAPI
		HcProcessEnumModulesEx(
			_In_ HANDLE ProcessHandle,
			HC_MODULE_CALLBACK_EVENT hcmCallback,
			LPARAM lParam);

	BOOLEAN
		HCAPI
		HcProcessReady(SIZE_T dwProcessId);

	BOOLEAN
		HCAPI
		HcProcessReadyEx(HANDLE hProcess);

	BOOLEAN
		HCAPI
		HcProcessInjectModuleManual(HANDLE hProcess,
			LPCWSTR lpPath);

	BOOLEAN
		HCAPI
		HcProcessSuspend(SIZE_T dwProcessId);

	BOOLEAN
		HCAPI
		HcProcessSuspendEx(HANDLE hProcess);

	BOOLEAN
		HCAPI
		HcProcessResume(SIZE_T dwProcessId);

	BOOLEAN
		HCAPI
		HcProcessResumeEx(HANDLE hProcess);

	SIZE_T
		WINAPI
		HcProcessModuleFileName(HANDLE hProcess,
			LPVOID lpv,
			LPWSTR lpFilename,
			DWORD nSize);

	BOOLEAN
		HCAPI
		HcProcessQueryByName(LPCWSTR lpProcessName,
			HC_PROCESS_CALLBACK_EVENT hcpCallback,
			LPARAM lParam);


	BOOLEAN
		HCAPI
		HcProcessSetPrivilegeA(HANDLE hProcess,
			LPCSTR Privilege, 
			BOOLEAN bEnablePrivilege 
		);


	BOOLEAN
		HCAPI
		HcProcessSetPrivilegeW(HANDLE hProcess,
			LPCWSTR Privilege,
			BOOLEAN bEnablePrivilege
		);

#if defined (__cplusplus)
}
#endif

#endif