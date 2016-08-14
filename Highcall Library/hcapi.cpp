#define _CRT_SECURE_NO_WARNINGS
/* GetModuleFileName should be replaced */

#include <ctime>
#include <stdio.h>

#include "hcapi.h"
#include "hcsyscall.h"
#include "hcfile.h"
#include "hcmodule.h"

NTSTATUS
HCAPI
HcGetTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated
) {
	NTSTATUS Status;
	TOKEN_ELEVATION Elevation;
	ULONG returnLength;

	Status = HcQueryInformationToken(TokenHandle,
		TokenElevation,
		&Elevation,
		sizeof(TOKEN_ELEVATION),
		&returnLength);

	if (NT_SUCCESS(Status))
	{
		*Elevated = !!Elevation.TokenIsElevated;
	}

	return Status;
}
/* Unreliable. */
SyscallIndex
HCAPI
HcSyscallIndex(LPCSTR lpName)
{
	BYTE buffer[10];
	HcFileReadModule(NTDLL, lpName, buffer, 10);

#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return buffer ? *(ULONG*)(buffer + 1) : 0;
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return buffer ? *(ULONG*)(buffer + 4) : 0;
#endif
}

/* Unreliable. */
SyscallIndex
HCAPI
HcSyscallIndex(LPCWSTR lpName)
{
	BYTE buffer[10];
	HcFileReadModule(NTDLL, lpName, buffer, 10);

#ifndef _WIN64
	/* mov eax, syscallindex */
	/* buffer + 1 is the syscall index, 0xB8 is the mov instruction */
	return buffer ? *(ULONG*)(buffer + 1) : 0;
#else
	/* mov r10, rcx */
	/* mov eax, syscall index */
	return buffer ? *(ULONG*)(buffer + 4) : 0;
#endif
}
VOID
HCAPI
HcCloseHandle(HANDLE hObject)
{
	__try
	{
		HcClose(hObject);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* Doesn't really matter, It's either already closed or It was never even opened. */
		SetLastError(STATUS_FAILED);
	}
}