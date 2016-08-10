#pragma once
#include "nttype.h"
#include "hcapi.h"

extern "C" SyscallIndex sciQueryInformationToken;
extern "C" NTSTATUS HcQueryInformationToken(_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength);

extern "C" SyscallIndex sciOpenProcessToken;
extern "C" NTSTATUS HcOpenProcessToken(_In_ HANDLE hProcess,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle);

extern "C" SyscallIndex sciResumeProcess;
extern "C" NTSTATUS HcResumeProcess(IN HANDLE ProcessHandle);

extern "C" SyscallIndex sciSuspendProcess;
extern "C" NTSTATUS HcSuspendProcess(IN HANDLE ProcessHandle);

extern "C" SyscallIndex sciAllocateVirtualMemory;
extern "C" NTSTATUS HcAllocateVirtualMemory(IN HANDLE hProcess,
	IN PVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

extern "C" SyscallIndex sciFreeVirtualMemory;
extern "C" NTSTATUS HcFreeVirtualMemory(IN HANDLE hProcess,
	IN PVOID* UBaseAddress,
	IN PSIZE_T URegionSize,
	IN ULONG FreeType);

extern "C" SyscallIndex sciResumeThread;
extern "C" NTSTATUS HcResumeThread(IN HANDLE ThreadHandle,
	OUT PULONG SuspendCount OPTIONAL);

extern "C" SyscallIndex sciQueryInformationThread;
extern "C" NTSTATUS HcQueryInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

extern "C" SyscallIndex sciCreateThread;
extern "C" NTSTATUS HcCreateThread(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended);

extern "C" SyscallIndex sciFlushInstructionCache;
extern "C" NTSTATUS HcFlushInstructionCache(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG NumberOfBytesToFlush);

extern "C" SyscallIndex sciOpenProcess;
extern "C" NTSTATUS HcOpenProcess(_Out_ PHANDLE ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

extern "C" SyscallIndex sciProtectVirtualMemory;
extern "C" NTSTATUS HcProtectVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection);

extern "C" SyscallIndex sciReadVirtualMemory;
extern "C" NTSTATUS HcReadVirtualMemory(HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

extern "C" SyscallIndex sciWriteVirtualMemory;
extern "C" NTSTATUS HcWriteVirtualMemory(HANDLE ProcessHandle,
	PVOID BaseAddress, 
	CONST VOID *Buffer,
	ULONG BufferSize, 
	PULONG NumberOfBytesWritten);

extern "C" SyscallIndex sciQueryInformationProcess;
extern "C" NTSTATUS HcQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

extern "C" SyscallIndex sciQuerySystemInformation;
extern "C" NTSTATUS HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength);

extern "C" SyscallIndex sciClose;
extern "C" NTSTATUS HcClose(HANDLE hObject);

extern "C" SyscallIndex sciQueryVirtualMemory;
extern "C" NTSTATUS HcQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength);