#pragma once
#include "type.h"

NTSTATUS NTAPI HcQueryInformationToken(_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength);

NTSTATUS NTAPI HcOpenProcessToken(_In_ HANDLE hProcess,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle);

NTSTATUS NTAPI HcResumeProcess(IN HANDLE ProcessHandle);

NTSTATUS NTAPI HcSuspendProcess(IN HANDLE ProcessHandle);

NTSTATUS NTAPI HcAllocateVirtualMemory(IN HANDLE hProcess,
	IN PVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);


NTSTATUS NTAPI HcFreeVirtualMemory(IN HANDLE hProcess,
	IN PVOID* UBaseAddress,
	IN PSIZE_T URegionSize,
	IN ULONG FreeType);

NTSTATUS NTAPI HcResumeThread(IN HANDLE ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL);

NTSTATUS NTAPI HcQueryInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS		ThreadInformationClass,
	OUT PVOID               ThreadInformation,
	IN ULONG                ThreadInformationLength,
	OUT PULONG              ReturnLength OPTIONAL);
NTSTATUS NTAPI HcCreateThread(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended);

NTSTATUS NTAPI HcFlushInstructionCache(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG NumberOfBytesToFlush);

NTSTATUS NTAPI HcOpenProcess(_Out_ PHANDLE ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

NTSTATUS NTAPI HcProtectVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection);
NTSTATUS NTAPI HcReadVirtualMemory(HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

NTSTATUS NTAPI HcWriteVirtualMemory(HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	CONST VOID *Buffer,
	SIZE_T BufferSize, 
	PSIZE_T NumberOfBytesWritten);

NTSTATUS NTAPI HcQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

NTSTATUS NTAPI HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength);

NTSTATUS NTAPI HcClose(HANDLE hObject);