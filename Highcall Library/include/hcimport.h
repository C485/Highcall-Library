#ifndef HC_IMPORT_H
#define HC_IMPORT_H

#include "../native/native.h"
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
	ACTIVATION_CONTEXT_INFO_CLASS Class, PACTIVATION_CONTEXT_BASIC_INFORMATION buffer,
	SIZE_T bufsize, SIZE_T *retlen);
HC_GLOBAL t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext;

typedef VOID(NTAPI *t_RtlFreeActivationContextStack) (IN PACTIVATION_CONTEXT_STACK Stack);
HC_GLOBAL t_RtlFreeActivationContextStack RtlFreeActivationContextStack;

typedef VOID(NTAPI *t_RtlFreeThreadActivationContextStack) (VOID);
HC_GLOBAL t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack;

typedef NTSTATUS(NTAPI *t_RtlActivateActivationContextEx) (ULONG flags, PTEB tebAddress, HANDLE handle, PULONG_PTR cookie);
HC_GLOBAL t_RtlActivateActivationContextEx RtlActivateActivationContextEx;

typedef ULONG (NTAPI *t_RtlNtStatusToDosError) (_In_ NTSTATUS Status);
HC_GLOBAL t_RtlNtStatusToDosError RtlNtStatusToDosError;

typedef VOID(NTAPI *t_RtlAcquirePebLock)(VOID);
HC_GLOBAL t_RtlAcquirePebLock RtlAcquirePebLock;

typedef VOID(NTAPI *t_RtlReleasePebLock)(VOID);
HC_GLOBAL t_RtlReleasePebLock RtlReleasePebLock;

typedef POBJECT_ATTRIBUTES(WINAPI *t_BaseFormatObjectAttributes) (OUT POBJECT_ATTRIBUTES ObjectAttributes,
	IN PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL,
	IN PUNICODE_STRING ObjectName);
HC_GLOBAL t_BaseFormatObjectAttributes BaseFormatObjectAttributes;

#endif