#ifndef HC_TOKEN_H
#define HC_TOKEN_H

#include <windows.h>
#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

PLUID
HCAPI
HcLookupPrivilegeValueW(IN LPCWSTR Name);

PLUID
HCAPI
HcLookupPrivilegeValueA(IN LPCSTR Name);

NTSTATUS
HCAPI
HcTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated);

#if defined (__cplusplus)
}
#endif

#endif