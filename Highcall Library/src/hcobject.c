#include "../include/hcobject.h"
#include "../native/native.h"
#include "../include/hcimport.h"
#include "../include/hcsyscall.h"
#include "../include/hcvirtual.h"

static PLARGE_INTEGER HCAPI TranslateTime(OUT PLARGE_INTEGER Timeout, IN DWORD dwMiliseconds)
{
	/* Check if this is an infinite wait, which means no timeout argument */
	if (dwMiliseconds == INFINITE) return NULL;

	/* Otherwise, convert the time to NT Format */
	Timeout->QuadPart = dwMiliseconds * -10000LL;
	return Timeout;
}

static HANDLE HCAPI TranslateHandle(IN HANDLE Handle)
{
	PRTL_USER_PROCESS_PARAMETERS Ppb = NtCurrentPeb()->ProcessParameters;
	
	switch (HandleToUlong(Handle))
	{
		case STD_INPUT_HANDLE:  return Ppb->StandardInput;
		case STD_OUTPUT_HANDLE: return Ppb->StandardOutput;
		case STD_ERROR_HANDLE:  return Ppb->StandardError;
	}
	
	return Handle;
}

/*
* @implemented
*/
DWORD
WINAPI
HcObjectWaitMultiple(IN DWORD nCount,
	IN CONST HANDLE *lpHandles,
	IN BOOL bWaitAll,
	IN DWORD dwMilliseconds)
{
	PLARGE_INTEGER TimePtr;
	LARGE_INTEGER Time;
	PHANDLE HandleBuffer;
	HANDLE Handle[8];
	DWORD i;
	NTSTATUS Status;

	/* Check if we have more handles then we locally optimize */
	if (nCount > 8)
	{
		/* Allocate a buffer for them */
		HandleBuffer = HcAlloc(nCount * sizeof(HANDLE));

		if (!HandleBuffer)
		{
			/* No buffer, fail the wait */
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return WAIT_FAILED;
		}
	}
	else
	{
		/* Otherwise, use our local buffer */
		HandleBuffer = Handle;
	}

	/* Copy the handles into our buffer and loop them all */
	RtlCopyMemory(HandleBuffer, (LPVOID)lpHandles, nCount * sizeof(HANDLE));
	for (i = 0; i < nCount; i++)
	{
		/* Check what kind of handle this is */
		HandleBuffer[i] = TranslateHandle(HandleBuffer[i]);
	}

	/* Convert the timeout */
	TimePtr = TranslateTime(&Time, dwMilliseconds);

	/* Do the wait */
	Status = HcWaitForMultipleObjects(nCount,
		HandleBuffer,
		bWaitAll ? WaitAll : WaitAny,
		FALSE,
		TimePtr);

	if (!NT_SUCCESS(Status))
	{
		/* Wait failed */
		SetLastError(RtlNtStatusToDosError(Status));
		Status = WAIT_FAILED;
	}

	/* Check if we didn't use our local buffer */
	if (HandleBuffer != Handle)
	{
		/* Free the allocated one */
		HcFree(HandleBuffer);
	}

	/* Return wait status */
	return Status;
}

/*
* @implemented
*/
DWORD 
HCAPI 
HcObjectWait(HANDLE hObject, IN DWORD dwMiliseconds)
{
	PLARGE_INTEGER TimePtr;
	LARGE_INTEGER Time;
	NTSTATUS Status;

	/* Get the real handle */
	hObject = TranslateHandle(hObject);

	/* Convert the timeout */
	TimePtr = TranslateTime(&Time, dwMiliseconds);

	/* Do the wait */
	Status = HcWaitForSingleObject(hObject, FALSE, TimePtr);
	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
	}

	return Status;
}

/*
* @implemented
*/
VOID
HCAPI
HcObjectClose(HANDLE hObject)
{
	__try
	{
		HcClose(hObject);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* Doesn't really matter, It's either already closed or It was never even opened. */
		SetLastError(RtlNtStatusToDosError(STATUS_FAILED));
	}
}