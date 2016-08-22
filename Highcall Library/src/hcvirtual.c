#include "../include/hcvirtual.h"
#include "../include/hcimport.h"
#include "../include/hcsyscall.h"

#include "../native/native.h"

/*
* @implemented
*/
LPVOID
HCAPI
HcVirtualAllocEx(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flAllocationType,
	IN DWORD flProtect)
{
	NTSTATUS Status;

	/* Handle any possible exceptions */
	__try
	{
		/* Allocate the memory */
		Status = HcAllocateVirtualMemory(hProcess,
		&lpAddress,
		0,
		&dwSize,
		flAllocationType,
		flProtect);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		/* By handle, I mean, totally ignore. */
	}

	/* Check for status */
	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		SetLastError(RtlNtStatusToDosError(Status));
		return NULL;
	}

	/* Return the allocated address */
	return lpAddress;
}

/*
* @implemented
*/
LPVOID
HCAPI
HcVirtualAlloc(IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flAllocationType,
	IN DWORD flProtect)
{
	/* Call the extended API */
	return HcVirtualAllocEx(NtCurrentProcess,
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect);
}

/*
* @implemented
*/
BOOL
HCAPI
HcVirtualFreeEx(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD dwFreeType)
{
	NTSTATUS Status;

	/* Validate size and flags */
	if (!(dwSize) || !(dwFreeType & MEM_RELEASE))
	{
		/* Free the memory */
		Status = HcFreeVirtualMemory(hProcess,
			&lpAddress,
			&dwSize,
			dwFreeType);

		if (!NT_SUCCESS(Status))
		{
			/* We failed */
			SetLastError(RtlNtStatusToDosError(Status));
			return FALSE;
		}

		/* Return success */
		return TRUE;
	}

	/* Invalid combo */
	SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
	return FALSE;
}

/*
* @implemented
*/
BOOL
HCAPI
HcVirtualFree(IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD dwFreeType)
{
	/* Call the extended API */
	return HcVirtualFreeEx(NtCurrentProcess,
		lpAddress,
		dwSize,
		dwFreeType);
}

/*
* @implemented
*/
BOOL
HCAPI
HcVirtualProtect(IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flNewProtect,
	OUT PDWORD lpflOldProtect)
{
	/* Call the extended API */
	return HcVirtualProtectEx(NtCurrentProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect);
}

/*
* @implemented
*/
BOOL
HCAPI
HcVirtualProtectEx(IN HANDLE hProcess,
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD flNewProtect,
	OUT PDWORD lpflOldProtect)
{
	NTSTATUS Status;

	/* Change the protection */
	Status = HcProtectVirtualMemory(hProcess,
		&lpAddress,
		&dwSize,
		flNewProtect,
		(PULONG)lpflOldProtect);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

/*
* @implemented
*/
BOOL
HCAPI
HcVirtualLock(IN LPVOID lpAddress,
	IN SIZE_T dwSize)
{
	NTSTATUS Status;
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	/* Lock the memory */
	Status = HcLockVirtualMemory(NtCurrentProcess,
		&BaseAddress,
		&RegionSize,
		MAP_PROCESS);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

/*
* @implemented
*/
SIZE_T
HCAPI
HcVirtualQuery(IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	IN SIZE_T dwLength)
{
	/* Call the extended API */
	return HcVirtualQueryEx(NtCurrentProcess,
		lpAddress,
		lpBuffer,
		dwLength);
}

/*
* @implemented
*/
SIZE_T
HCAPI
HcVirtualQueryEx(IN HANDLE hProcess,
	IN LPCVOID lpAddress,
	OUT PMEMORY_BASIC_INFORMATION lpBuffer,
	IN SIZE_T dwLength)
{
	NTSTATUS Status;
	SIZE_T ResultLength;

	/* Query basic information */
	Status = HcQueryVirtualMemory(hProcess,
		(LPVOID)lpAddress,
		MemoryBasicInformation,
		lpBuffer,
		dwLength,
		&ResultLength);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		SetLastError(RtlNtStatusToDosError(Status));
		return 0;
	}

	/* Return the length returned */
	return ResultLength;
}

/*
* @implemented
*/
BOOL
HCAPI
HcVirtualUnlock(IN LPVOID lpAddress,
	IN SIZE_T dwSize)
{
	NTSTATUS Status;
	SIZE_T RegionSize = dwSize;
	PVOID BaseAddress = lpAddress;

	/* Lock the memory */
	Status = HcUnlockVirtualMemory(NtCurrentProcess,
		&BaseAddress,
		&RegionSize,
		MAP_PROCESS);

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

/*
@implemented

	Should only be called in correlation with HcFree.

*/
PVOID HCAPI HcAlloc(IN SIZE_T Size)
{
	/* Call the API. */
	return HcVirtualAlloc(NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

/*
@implemented

	Should only be called in correlation with HcAlloc.

*/
VOID HCAPI HcFree(IN LPVOID lpAddress)
{
	HcVirtualFree(lpAddress, 0, MEM_RELEASE);
}