#ifndef HC_API_H
#define HC_API_H

#include <windows.h>
#include "native.h"
#include "hcdef.h"

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

#endif

#if defined (__cplusplus)
}
#endif