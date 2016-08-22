#ifndef HC_MEM_H
#define HC_MEM_H

#include "hcdef.h"

#define MAP_PROCESS                                         1
#define MAP_SYSTEM                                          2

#if defined (__cplusplus)
extern "C" {
#endif

	LPVOID HCAPI HcVirtualAllocEx(IN HANDLE hProcess,
			IN LPVOID lpAddress,
			IN SIZE_T dwSize,
			IN DWORD flAllocationType,
			IN DWORD flProtect);

	LPVOID HCAPI HcVirtualAlloc(IN LPVOID lpAddress,
			IN SIZE_T dwSize,
			IN DWORD flAllocationType,
			IN DWORD flProtect);

	BOOL HCAPI HcVirtualFreeEx(IN HANDLE hProcess,
			IN LPVOID lpAddress,
			IN SIZE_T dwSize,
			IN DWORD dwFreeType);

	BOOL HCAPI HcVirtualFree(IN LPVOID lpAddress,
			IN SIZE_T dwSize,
			IN DWORD dwFreeType);

	BOOL HCAPI HcVirtualProtect(IN LPVOID lpAddress,
			IN SIZE_T dwSize,
			IN DWORD flNewProtect,
			OUT PDWORD lpflOldProtect);

	BOOL HCAPI HcVirtualProtectEx(IN HANDLE hProcess,
			IN LPVOID lpAddress,
			IN SIZE_T dwSize,
			IN DWORD flNewProtect,
			OUT PDWORD lpflOldProtect);
	
	BOOL HCAPI HcVirtualLock(IN LPVOID lpAddress,
			IN SIZE_T dwSize);

	SIZE_T HCAPI HcVirtualQuery(IN LPCVOID lpAddress,
		OUT PMEMORY_BASIC_INFORMATION lpBuffer,
		IN SIZE_T dwLength);

	SIZE_T HCAPI HcVirtualQueryEx(IN HANDLE hProcess,
		IN LPCVOID lpAddress,
		OUT PMEMORY_BASIC_INFORMATION lpBuffer,
		IN SIZE_T dwLength);

	BOOL HCAPI HcVirtualUnlock(IN LPVOID lpAddress,
		IN SIZE_T dwSize);

	PVOID HCAPI HcAlloc(IN SIZE_T Size);

	VOID HCAPI HcFree(IN LPVOID lpAddress);

#if defined (__cplusplus)
}
#endif

#endif