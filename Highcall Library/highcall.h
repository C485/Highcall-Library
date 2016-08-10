#pragma once
#include <windows.h>
#include "hcdef.h"
#include "hcsyscall.h"
#include "hcimport.h"
#include "hctrampoline.h"

typedef ULONG HIGHCALL_STATUS;

#define HIGHCALL_ADVANCE(Status)				((HIGHCALL_STATUS)(Status) >= 0)
#define HIGHCALL_SUCCESS						((HIGHCALL_STATUS)0x00000000L)
#define HIGHCALL_FAILED							((HIGHCALL_STATUS)0xC0000001L)
#define HIGHCALL_OPENPROCESSTOKEN_UNDEFINED		((HIGHCALL_STATUS)0xC0000002L)
#define HIGHCALL_RTLGETVERSION_UNDEFINED		((HIGHCALL_STATUS)0xC0000003L)

extern BOOLEAN HcGlobalElevated;
extern ULONG HcGlobalWindowsVersion;

extern HMODULE NTDLL;
extern HMODULE USER32;
extern HMODULE KERNEL32;

extern "C" SyscallIndex sciQueryInformationToken;
extern "C" SyscallIndex sciOpenProcessToken;
extern "C" SyscallIndex sciResumeProcess;
extern "C" SyscallIndex sciSuspendProcess;
extern "C" SyscallIndex sciAllocateVirtualMemory;
extern "C" SyscallIndex sciFreeVirtualMemory;
extern "C" SyscallIndex sciQueryInformationThread;
extern "C" SyscallIndex sciCreateThread;
extern "C" SyscallIndex sciFlushInstructionCache;
extern "C" SyscallIndex sciOpenProcess;
extern "C" SyscallIndex sciProtectVirtualMemory;
extern "C" SyscallIndex sciReadVirtualMemory;
extern "C" SyscallIndex sciWriteVirtualMemory;
extern "C" SyscallIndex sciQueryInformationProcess;
extern "C" SyscallIndex sciQuerySystemInformation;
extern "C" SyscallIndex sciClose;
extern "C" SyscallIndex sciQueryVirtualMemory;
extern "C" SyscallIndex sciResumeThread;

extern t_RtlActivateActivationContextEx RtlActivateActivationContextEx;
extern t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack;
extern t_RtlFreeActivationContextStack RtlFreeActivationContextStack;
extern t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext;
extern t_RtlAllocateActivationContextStack RtlAllocateActivationContextStack;
extern t_LdrLoadDll LdrLoadDll;
extern t_RtlGetVersion RtlGetVersion;
extern t_RtlEqualUnicodeString RtlEqualUnicodeString;
extern t_RtlInitUnicodeString RtlInitUnicodeString;

extern tGetWindowThreadProcessId HcGetWindowThreadProcessId;
extern tGetCursorPos HcGetCursorPos;
extern tPostMessageA HcPostMessageA;
extern tPostMessageW HcPostMessageW;
extern tSendMessageA HcSendMessageA;
extern tSendMessageW HcSendMessageW;
extern tCreateRemoteThread HcCreateRemoteThread;

HIGHCALL_STATUS HCAPI HcInitialize();
