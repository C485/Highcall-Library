#include "..\include\hcsyscall.h"
#include "..\include\hcmodule.h"
#include "..\include\hcfile.h"

/* Unreliable. */
SyscallIndex
HCAPI
HcSyscallIndexA(LPCSTR lpName)
{
	BYTE buffer[10];
	if (!HcFileReadModuleA(NTDLL, lpName, buffer, 10))
	{
		return 0;
	}

#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return *(ULONG*)(buffer + 1);
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return *(ULONG*)(buffer + 4);
#endif
}

/* Unreliable. */
SyscallIndex
HCAPI
HcSyscallIndexW(LPCWSTR lpName)
{
	BYTE buffer[10];
	if (!HcFileReadModuleW(NTDLL, lpName, buffer, 10))
	{
		return 0;
	}

#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return *(ULONG*)(buffer + 1);
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return *(ULONG*)(buffer + 4);
#endif
}