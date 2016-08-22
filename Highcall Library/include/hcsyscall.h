#ifndef HC_SYSCALL_H
#define HC_SYSCALL_H

#include "../native/native.h"
#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

SyscallIndex
HCAPI
HcSyscallIndexA(LPCSTR lpName);

SyscallIndex
HCAPI
HcSyscallIndexW(LPCWSTR lpName); 

#if defined (__cplusplus)
}
#endif

HC_GLOBAL SyscallIndex sciQueryInformationToken;
HC_GLOBAL NTSTATUS HcQueryInformationToken(_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) LPVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength);

HC_GLOBAL SyscallIndex sciOpenProcessToken;
HC_GLOBAL NTSTATUS HcOpenProcessToken(_In_ HANDLE hProcess,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle);

HC_GLOBAL SyscallIndex sciResumeProcess;
HC_GLOBAL NTSTATUS HcResumeProcess(IN HANDLE ProcessHandle);

HC_GLOBAL SyscallIndex sciSuspendProcess;
HC_GLOBAL NTSTATUS HcSuspendProcess(IN HANDLE ProcessHandle);

HC_GLOBAL SyscallIndex sciAllocateVirtualMemory;
HC_GLOBAL NTSTATUS HcAllocateVirtualMemory(IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

HC_GLOBAL SyscallIndex sciFreeVirtualMemory;
HC_GLOBAL NTSTATUS HcFreeVirtualMemory(IN HANDLE hProcess,
	IN LPVOID* UBaseAddress,
	IN PSIZE_T URegionSize,
	IN ULONG FreeType);

HC_GLOBAL SyscallIndex sciResumeThread;
HC_GLOBAL NTSTATUS HcResumeThread(IN HANDLE ThreadHandle,
	OUT PULONG SuspendCount OPTIONAL);

HC_GLOBAL SyscallIndex sciQueryInformationThread;
HC_GLOBAL NTSTATUS HcQueryInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT LPVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

HC_GLOBAL SyscallIndex sciCreateThread;
HC_GLOBAL NTSTATUS HcCreateThread(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended);

HC_GLOBAL SyscallIndex sciFlushInstructionCache;
HC_GLOBAL NTSTATUS HcFlushInstructionCache(IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress,
	IN SIZE_T NumberOfBytesToFlush);

HC_GLOBAL SyscallIndex sciOpenProcess;
HC_GLOBAL NTSTATUS HcOpenProcess(_Out_ PHANDLE ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

HC_GLOBAL SyscallIndex sciProtectVirtualMemory;
HC_GLOBAL NTSTATUS HcProtectVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection);

HC_GLOBAL SyscallIndex sciReadVirtualMemory;
HC_GLOBAL NTSTATUS HcReadVirtualMemory(HANDLE ProcessHandle,
	LPVOID BaseAddress,
	LPVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

HC_GLOBAL SyscallIndex sciWriteVirtualMemory;
HC_GLOBAL NTSTATUS HcWriteVirtualMemory(HANDLE ProcessHandle,
	LPVOID BaseAddress, 
	CONST VOID *Buffer,
	SIZE_T BufferSize, 
	PSIZE_T NumberOfBytesWritten);

HC_GLOBAL SyscallIndex sciQueryInformationProcess;
HC_GLOBAL NTSTATUS HcQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) LPVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

HC_GLOBAL SyscallIndex sciQuerySystemInformation;
HC_GLOBAL NTSTATUS HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) LPVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength);

HC_GLOBAL SyscallIndex sciClose;
HC_GLOBAL NTSTATUS HcClose(HANDLE hObject);

HC_GLOBAL SyscallIndex sciQueryVirtualMemory;
HC_GLOBAL NTSTATUS HcQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT LPVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength);

HC_GLOBAL SyscallIndex sciAdjustPrivilegesToken;
HC_GLOBAL NTSTATUS HcAdjustPrivilegesToken(HANDLE TokenHandle,
	BOOLEAN 	DisableAllPrivileges,
	PTOKEN_PRIVILEGES 	NewState,
	DWORD 	BufferLength,
	PTOKEN_PRIVILEGES 	PreviousState,
	PDWORD 	ReturnLength);

HC_GLOBAL SyscallIndex sciSetInformationThread;
HC_GLOBAL NTSTATUS HcSetInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

HC_GLOBAL SyscallIndex sciOpenDirectoryObject;
HC_GLOBAL NTSTATUS HcOpenDirectoryObject(OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

HC_GLOBAL SyscallIndex sciCreateThreadEx;
HC_GLOBAL NTSTATUS HcCreateThreadEx(_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList);

HC_GLOBAL SyscallIndex sciWaitForSingleObject;
HC_GLOBAL NTSTATUS HcWaitForSingleObject(IN HANDLE hObject,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER Timeout);

HC_GLOBAL SyscallIndex sciWaitForMultipleObjects;
HC_GLOBAL NTSTATUS HcWaitForMultipleObjects(IN ULONG ObjectCount,
	IN PHANDLE HandleArray,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

HC_GLOBAL SyscallIndex sciUnlockVirtualMemory;
HC_GLOBAL NTSTATUS HcUnlockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToUnlock,
	IN ULONG MapType);


HC_GLOBAL SyscallIndex sciLockVirtualMemory;
HC_GLOBAL NTSTATUS HcLockVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T NumberOfBytesToLock,
	IN ULONG MapType);

#endif