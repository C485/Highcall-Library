#pragma once
#include "native.h"

typedef NTSTATUS(NTAPI *t_RtlGetVersion) (_Out_ PRTL_OSVERSIONINFOW lpInformation);

typedef BOOLEAN(NTAPI *t_RtlEqualUnicodeString) (
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive
	);

typedef VOID(NTAPI *t_RtlInitUnicodeString) (
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);

typedef NTSTATUS(NTAPI *t_LdrLoadDll) (IN PWCHAR PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle);

typedef NTSTATUS(NTAPI *t_RtlAllocateActivationContextStack) (IN PACTIVATION_CONTEXT_STACK *Stack);

typedef NTSTATUS(NTAPI *t_RtlQueryInformationActivationContext) (ULONG flags, HANDLE handle, PVOID subinst,
	ULONG Class, PVOID buffer,
	SIZE_T bufsize, SIZE_T *retlen);

typedef VOID(NTAPI *t_RtlFreeActivationContextStack) (IN PACTIVATION_CONTEXT_STACK Stack);

typedef VOID(NTAPI *t_RtlFreeThreadActivationContextStack) (VOID);

typedef NTSTATUS(NTAPI *t_RtlActivateActivationContextEx) (ULONG flags, PTEB tebAddress, HANDLE handle, PULONG_PTR cookie);