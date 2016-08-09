#include "syscall.h"
#include <stdio.h>

SyscallIndex sciQueryInformationToken = HcSyscallIndex("NtQueryInformationToken");
SyscallIndex sciOpenProcessToken = HcSyscallIndex("NtOpenProcessToken");
SyscallIndex sciResumeProcess = HcSyscallIndex("NtResumeProcess");
SyscallIndex sciSuspendProcess = HcSyscallIndex("NtSuspendProcess");
SyscallIndex sciAllocateVirtualMemory = HcSyscallIndex("NtAllocateVirtualMemory");
SyscallIndex sciFreeVirtualMemory = HcSyscallIndex("NtFreeVirtualMemory");
SyscallIndex sciResumeThread = HcSyscallIndex("NtResumeThread");
SyscallIndex sciQueryInformationThread = HcSyscallIndex("NtQueryInformationThread");
SyscallIndex sciCreateThread = HcSyscallIndex("NtCreateThread");
SyscallIndex sciFlushInstructionCache = HcSyscallIndex("NtFlushInstructionCache");
SyscallIndex sciOpenProcess = HcSyscallIndex("NtOpenProcess");
SyscallIndex sciProtectVirtualMemory = HcSyscallIndex("NtProtectVirtualMemory");
SyscallIndex sciReadVirtualMemory = HcSyscallIndex("NtReadVirtualMemory");
SyscallIndex sciWriteVirtualMemory = HcSyscallIndex("NtWriteVirtualMemory");
SyscallIndex sciQueryInformationProcess = HcSyscallIndex("NtQueryInformationProcess");
SyscallIndex sciQuerySystemInformation = HcSyscallIndex("NtQuerySystemInformation");
SyscallIndex sciClose = HcSyscallIndex("NtClose");