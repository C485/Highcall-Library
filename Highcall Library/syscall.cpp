#include "syscall.h"
#include "hcapi.h"

static SyscallIndex sciFlushInstructionCache = HcSyscallIndex("NtFlushInstructionCache");
static SyscallIndex sciOpenProcess = HcSyscallIndex("NtOpenProcess");
static SyscallIndex sciProtectVirtualMemory = HcSyscallIndex("NtProtectVirtualMemory");
static SyscallIndex sciReadVirtualMemory = HcSyscallIndex("NtReadVirtualMemory");
static SyscallIndex sciWriteVirtualMemory = HcSyscallIndex("NtWriteVirtualMemory");
static SyscallIndex sciQueryInformationProcess = HcSyscallIndex("NtQueryInformationProcess");
static SyscallIndex sciQuerySystemInformation = HcSyscallIndex("NtQuerySystemInformation");
static SyscallIndex sciClose = HcSyscallIndex("NtClose");
static SyscallIndex sciCreateThread = HcSyscallIndex("NtCreateThread");
static SyscallIndex sciQueryInformationThread = HcSyscallIndex("NtQueryInformationThread");
static SyscallIndex sciResumeThread = HcSyscallIndex("NtResumeThread");
static SyscallIndex sciFreeVirtualMemory = HcSyscallIndex("NtFreeVirtualMemory");
static SyscallIndex sciAllocateVirtualMemory = HcSyscallIndex("NtAllocateVirtualMemory");
static SyscallIndex sciSuspendProcess = HcSyscallIndex("NtSuspendProcess");
static SyscallIndex sciResumeProcess = HcSyscallIndex("NtResumeProcess");
static SyscallIndex sciOpenProcessToken = HcSyscallIndex("NtOpenProcessToken");
static SyscallIndex sciQueryInformationToken = HcSyscallIndex("NtQueryInformationToken");

__declspec(naked) NTSTATUS NTAPI HcQueryInformationToken(_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_(TokenInformationLength) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength)
{
	__asm
	{
		mov eax, [sciQueryInformationToken]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcOpenProcessToken(_In_ HANDLE hProcess,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle)
{
	__asm
	{
		mov eax, [sciOpenProcessToken]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcResumeProcess(IN HANDLE ProcessHandle)
{
	__asm
	{
		mov eax, [sciResumeProcess]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcSuspendProcess(IN HANDLE ProcessHandle)
{
	__asm
	{
		mov eax, [sciSuspendProcess]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcAllocateVirtualMemory(IN HANDLE hProcess,
	IN PVOID* UBaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T URegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect)
{
	__asm
	{
		mov eax, [sciAllocateVirtualMemory]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}


__declspec(naked) NTSTATUS NTAPI HcFreeVirtualMemory(IN HANDLE hProcess,
	IN PVOID* UBaseAddress,
	IN PSIZE_T URegionSize,
	IN ULONG FreeType)
{
	__asm
	{
		mov eax, [sciFreeVirtualMemory]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcResumeThread(IN HANDLE ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL)
{
	__asm
	{
		mov eax, [sciResumeThread]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcQueryInformationThread(IN HANDLE ThreadHandle,
	IN THREADINFOCLASS		ThreadInformationClass,
	OUT PVOID               ThreadInformation,
	IN ULONG                ThreadInformationLength,
	OUT PULONG              ReturnLength OPTIONAL)
{
	__asm
	{
		mov eax, [sciQueryInformationThread]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcCreateThread(OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended)
{
	__asm
	{
		mov eax, [sciCreateThread]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcFlushInstructionCache(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG NumberOfBytesToFlush)
{
	__asm
	{
		mov eax, [sciFlushInstructionCache]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcOpenProcess
(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
) {
	__asm
	{
		mov eax, [sciOpenProcess]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcProtectVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection)
{
	__asm
	{
		mov eax, [sciProtectVirtualMemory]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
{
	__asm
	{
		mov eax, [sciReadVirtualMemory]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, CONST VOID *Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
	__asm
	{
		mov eax, [sciWriteVirtualMemory]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength)
{
	__asm
	{
		mov eax, [sciQueryInformationProcess]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength)
{
	__asm
	{
		mov eax, [sciQuerySystemInformation]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}

__declspec(naked) NTSTATUS NTAPI HcClose(HANDLE hObject)
{
	__asm
	{
		mov eax, [sciClose]
		xor ecx, ecx
		lea edx, [esp + 4]
		call fs : [0xC0]
		retn
	}
}