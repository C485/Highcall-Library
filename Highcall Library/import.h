#pragma once
#include <windows.h>
#include "type.h"

typedef NTSTATUS(NTAPI *t_RtlGetVersion) (_Out_ PRTL_OSVERSIONINFOW lpInformation);
extern t_RtlGetVersion RtlGetVersion;

typedef BOOLEAN(NTAPI *t_RtlEqualUnicodeString) (
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive
	);
extern t_RtlEqualUnicodeString RtlEqualUnicodeString;

typedef VOID(NTAPI *t_RtlInitUnicodeString) (
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);
extern t_RtlInitUnicodeString RtlInitUnicodeString;

typedef NTSTATUS(NTAPI *t_LdrLoadDll) (IN PWCHAR PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle);
extern t_LdrLoadDll LdrLoadDll;

typedef NTSTATUS(NTAPI *t_RtlAllocateActivationContextStack) (IN PACTIVATION_CONTEXT_STACK *Stack);
extern t_RtlAllocateActivationContextStack RtlAllocateActivationContextStack;

typedef NTSTATUS(NTAPI *t_RtlQueryInformationActivationContext) (ULONG flags, HANDLE handle, PVOID subinst,
	ULONG Class, PVOID buffer,
	SIZE_T bufsize, SIZE_T *retlen);
extern t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext;

typedef VOID(NTAPI *t_RtlFreeActivationContextStack) (IN PACTIVATION_CONTEXT_STACK Stack);
extern t_RtlFreeActivationContextStack RtlFreeActivationContextStack;

typedef VOID(NTAPI *t_RtlFreeThreadActivationContextStack) (VOID);
extern t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack;

typedef NTSTATUS(NTAPI *t_RtlActivateActivationContextEx) (ULONG flags, PTEB tebAddress, HANDLE handle, PULONG_PTR cookie);
extern t_RtlActivateActivationContextEx RtlActivateActivationContextEx;