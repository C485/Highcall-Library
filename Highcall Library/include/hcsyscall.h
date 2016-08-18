#ifndef HC_SYSCALL_H
#define HC_SYSCALL_H

#include "../native/native.h"
#include "hcdef.h"

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
	IN OUT LPVOID *BaseAddress,
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
	BOOL 	DisableAllPrivileges,
	PTOKEN_PRIVILEGES 	NewState,
	DWORD 	BufferLength,
	PTOKEN_PRIVILEGES 	PreviousState,
	PDWORD 	ReturnLength);

#endif