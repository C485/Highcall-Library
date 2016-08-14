#pragma once
#include <windows.h>
#include "native.h"
#include "hcdef.h"

NTSTATUS
HCAPI
HcGetTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated
);

SyscallIndex
HCAPI
HcSyscallIndex(LPCSTR lpName);

SyscallIndex
HCAPI
HcSyscallIndex(LPCWSTR lpName);

VOID
HCAPI
HcCloseHandle(HANDLE hObject);
