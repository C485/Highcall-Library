#ifndef HC_API_H
#define HC_API_H

#include <windows.h>
#include "../native/native.h"
#include "../include/hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

NTSTATUS
HCAPI
HcGetTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated
);

SyscallIndex
HCAPI
HcSyscallIndexA(LPCSTR lpName);

SyscallIndex
HCAPI
HcSyscallIndexW(LPCWSTR lpName);

VOID
HCAPI
HcCloseHandle(HANDLE hObject);

#if defined (__cplusplus)
}
#endif

#endif
