#ifndef HC_IMPORT_H
#define HC_IMPORT_H

#include "native.h"
#include "hcdef.h"

typedef NTSTATUS(NTAPI *t_RtlGetVersion) (_Out_ PRTL_OSVERSIONINFOW lpInformation);
HC_GLOBAL t_RtlGetVersion RtlGetVersion;

typedef BOOLEAN(NTAPI *t_RtlEqualUnicodeString) (
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive
	);
HC_GLOBAL t_RtlEqualUnicodeString RtlEqualUnicodeString;

typedef VOID(NTAPI *t_RtlInitUnicodeString) (
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);
HC_GLOBAL t_RtlInitUnicodeString RtlInitUnicodeString;

typedef NTSTATUS(NTAPI *t_LdrLoadDll) (IN PWCHAR PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle);
HC_GLOBAL t_LdrLoadDll LdrLoadDll;

typedef NTSTATUS(NTAPI *t_RtlAllocateActivationContextStack) (IN PACTIVATION_CONTEXT_STACK *Stack);
HC_GLOBAL t_RtlAllocateActivationContextStack RtlAllocateActivationContextStack;

typedef NTSTATUS(NTAPI *t_RtlQueryInformationActivationContext) (ULONG flags, HANDLE handle, PBYTE subinst,
	ULONG Class, PBYTE buffer,
	SIZE_T bufsize, SIZE_T *retlen);
HC_GLOBAL t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext;

typedef VOID(NTAPI *t_RtlFreeActivationContextStack) (IN PACTIVATION_CONTEXT_STACK Stack);
HC_GLOBAL t_RtlFreeActivationContextStack RtlFreeActivationContextStack;

typedef VOID(NTAPI *t_RtlFreeThreadActivationContextStack) (VOID);
HC_GLOBAL t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack;

typedef NTSTATUS(NTAPI *t_RtlActivateActivationContextEx) (ULONG flags, PTEB tebAddress, HANDLE handle, PULONG_PTR cookie);
HC_GLOBAL t_RtlActivateActivationContextEx RtlActivateActivationContextEx;

#endif