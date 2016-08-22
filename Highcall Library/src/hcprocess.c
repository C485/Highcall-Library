#define _CRT_SECURE_NO_WARNINGS

#include "../include/hcprocess.h"
#include "../include/hcstring.h"
#include "../include/hcsyscall.h"
#include "../include/hcimport.h"
#include "../include/hcfile.h"
#include "../include/hctoken.h"
#include "../include/hcpe.h"
#include "../include/hcmodule.h"
#include "../include/hcobject.h"
#include "../include/hcvirtual.h"

BOOLEAN
HCAPI
HcProcessExitCode(IN SIZE_T dwProcessId,
	IN LPDWORD lpExitCode)
{
	HANDLE hProcess;
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	hProcess = HcProcessOpen(dwProcessId, 
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

	if (!hProcess)
	{
		return FALSE;
	}

	/* Ask the kernel */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcessBasic,
		sizeof(ProcessBasic),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		HcClose(hProcess);
		return FALSE;
	}

	*lpExitCode = (DWORD)ProcessBasic.ExitStatus;

	HcClose(hProcess);
	return TRUE;
}

BOOLEAN 
HCAPI
HcProcessExitCodeEx(IN HANDLE hProcess,
	IN LPDWORD lpExitCode)
{
	PROCESS_BASIC_INFORMATION ProcessBasic;
	NTSTATUS Status;

	/* Ask the kernel */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation, 
		&ProcessBasic,
		sizeof(ProcessBasic),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	*lpExitCode = (DWORD) ProcessBasic.ExitStatus;

	return TRUE;
}

HANDLE
HCAPI
HcProcessOpen(SIZE_T dwProcessId, ACCESS_MASK DesiredAccess)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	HANDLE hProcess;

	cid.UniqueProcess = (HANDLE)dwProcessId;
	cid.UniqueThread = 0;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	Status = HcOpenProcess(&hProcess, DesiredAccess, &oa, &cid);

	SetLastError(RtlNtStatusToDosError(Status));
	if (NT_SUCCESS(Status))
	{
		return hProcess;
	}

	return 0;
}

BOOLEAN
HCAPI
HcProcessReadyEx(HANDLE hProcess)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PROCESS_BASIC_INFORMATION ProcInfo;
	DWORD ExitCode;
	DWORD Len;

	/* Will fail if there is a mismatch in compiler architecture. */
	if (!HcProcessExitCodeEx(hProcess, &ExitCode) || ExitCode != STILL_ACTIVE)
	{
		return FALSE;
	}

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	SetLastError(RtlNtStatusToDosError(Status));
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	
	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData, 
		sizeof(LoaderData),
		NULL) || !LoaderData)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN
HCAPI
HcProcessReady(SIZE_T dwProcessId)
{
	BOOLEAN Success;
	HANDLE hProcess;

	if (!(hProcess = HcProcessOpen(dwProcessId,
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
	{
		return FALSE;
	}

	/* Ensure we didn't find it before ntdll was loaded */
	Success = HcProcessReadyEx(hProcess);

	HcClose(hProcess);

	return Success;
}

#pragma region Internal Manual Map Code

static
SIZE_T
HCAPI MmInternalResolve(PVOID lParam)
{
	PMANUAL_MAP ManualInject;
	HMODULE hModule;
	SIZE_T Index;
	SIZE_T Function;
	SIZE_T Count;
	SIZE_T Delta;
	PSIZE_T FunctionPointer;
	PWORD ImportList;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_MAP)lParam;

	pIBR = ManualInject->BaseRelocation;
	Delta = (SIZE_T)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			ImportList = (PWORD)(pIBR + 1);

			for (Index = 0; Index<Count; Index++)
			{
				if (ImportList[Index])
				{
					FunctionPointer = (PSIZE_T)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (ImportList[Index] & 0xFFF)));
					*FunctionPointer += Delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	/* Manually load all the library imports */
	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		/* Import each */
		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				/* By ordinal */
				Function = (SIZE_T)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				/* By name */
				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (SIZE_T)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

SIZE_T HCAPI MmInternalResolved()
{
	return 0;
}
#pragma endregion

static
BOOLEAN
HCAPI
HcParameterVerifyInjectModuleManual(PVOID Buffer)
{
	PIMAGE_NT_HEADERS pHeaderNt;
	pHeaderNt = HcPEGetNtHeader(Buffer);

	return pHeaderNt && (pHeaderNt->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

/*
@inprogress

	Inserts a dynamic library's code inside of a process, without the use of any windows library linking code.
	This ensure that any code trying to locate a dll will not succeed, as there is no record of library loading happening.

	The code currently only supports 32bit to 32bit.

	For 64bit to 32bit, the internal resolving code will need to be in either shellcode, or an assembly file.
	For 32bit to 64bit, same story.

	RETURN 
		- A boolean indicating success
		GetLastError() for a diagnosis.
*/
BOOLEAN
HCAPI
HcProcessInjectModuleManual(HANDLE hProcess,
	LPCWSTR lpPath)
{
	HC_FILE_INFORMATION fileInformation;
	MANUAL_MAP ManualInject;

	PIMAGE_DOS_HEADER pHeaderDos;
	PIMAGE_NT_HEADERS pHeaderNt;
	PIMAGE_SECTION_HEADER pHeaderSection;

	HANDLE hThread, hFile;
	PVOID ImageBuffer, LoaderBuffer, FileBuffer;
	DWORD ExitCode, SectionIndex;
	SIZE_T BytesWritten, BytesRead;

	/* Check if we attempted to inject too early. */
	if (!HcProcessReadyEx(hProcess))
	{
		SetLastError(RtlNtStatusToDosError(STATUS_PENDING));
		return FALSE;
	}

	/* Get the basic information about the file */
	if (!HcFileQueryInformationW(lpPath, &fileInformation))
	{
		return FALSE;
	}

	/* Allocate for the file information */
	FileBuffer = HcAlloc(fileInformation.Size);

	/* Read the file */
	hFile = CreateFileW(lpPath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (!ReadFile(hFile,
		FileBuffer,
		fileInformation.Size,
		&BytesRead,
		NULL) || BytesRead != fileInformation.Size)
	{
		HcFree(FileBuffer);
		HcClose(hFile);

		return FALSE;
	}

	HcObjectClose(hFile);

	/* Verify this is a PE DLL */
	if (!HcParameterVerifyInjectModuleManual(FileBuffer))
	{
		HcFree(FileBuffer);
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		return FALSE;
	}

	pHeaderDos = HcPEGetDosHeader(FileBuffer);
	pHeaderNt = HcPEGetNtHeader(FileBuffer);

	/* Allocate for the code/data of the dll */
	ImageBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		pHeaderNt->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!ImageBuffer)
	{
		HcFree(FileBuffer);
		return FALSE;
	}

	/* Write the code/data to the target executable */
	if (!HcProcessWriteMemory(hProcess,
		ImageBuffer,
		FileBuffer,
		pHeaderNt->OptionalHeader.SizeOfHeaders,
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		HcFree(FileBuffer);
		return FALSE;
	}

	pHeaderSection = (PIMAGE_SECTION_HEADER)(pHeaderNt + 1);

	/* Write sections of the dll to the process, not guaranteed to succeed, so no check. */
	for (SectionIndex = 0; SectionIndex < pHeaderNt->FileHeader.NumberOfSections; SectionIndex++)
	{
		/* This writes to relative locations of our loaded executable. 
		
			ImageBuffer points to the base of the library.
			.VirtualAddress points to the relative offset from the base of the library to the section.
			
			FileBuffer points to the base of the file.
			.PointerToRawData points to the relative offset from the file to the section.
		*/

		HcProcessWriteMemory(hProcess,
			(PVOID)((LPBYTE)ImageBuffer + pHeaderSection[SectionIndex].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pHeaderSection[SectionIndex].PointerToRawData),
			pHeaderSection[SectionIndex].SizeOfRawData,
			&BytesWritten);
	}

	/* Allocate code for our function */
	LoaderBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!LoaderBuffer)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		HcFree(FileBuffer);

		return FALSE;
	}

	memset(&ManualInject, 0, sizeof(MANUAL_MAP));

	/*
		MANUAL_MAP struct
	
		ImageBase = allocated image location.
		NtHeaders = allocated image location, added with relative address pointing Nt header.
		BaseRelocation = allocated image buffer + relative address of relocation.
		ImportDirectory = allocated image buffer + relative import directory

		LoadLibraryA - this needs to be reworked.
			right now, this function is located by looking into our own address.
			this will not work for when the executable does not match the target executable architecture. (cross dll injection)

		GetProcAddress, same as above.
	*/

	ManualInject.ImageBase = ImageBuffer;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ImageBuffer + pHeaderDos->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;

	/* Set the manual map information */
	if (!HcProcessWriteMemory(hProcess,
		LoaderBuffer,
		&ManualInject,
		sizeof(MANUAL_MAP),
		&BytesWritten))
	{
		return FALSE;
	}

	/* Set the code which will resolve imports, relocations */
	if (!HcProcessWriteMemory(hProcess,
		(PVOID)((PMANUAL_MAP)LoaderBuffer + 1),
		MmInternalResolve,
		(DWORD)MmInternalResolved - (DWORD)MmInternalResolve,
		&BytesWritten))
	{
		return FALSE;
	}

	/* Execute the code in a new thread */
	hThread = HcProcessCreateThread(hProcess,
		(LPTHREAD_START_ROUTINE)((PMANUAL_MAP)LoaderBuffer + 1),
		LoaderBuffer,
		0);

	if (!hThread)
	{
		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcFree(FileBuffer);
		return FALSE;
	}

	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);

	/* Did the thread exit? */
	GetExitCodeThread(hThread, &ExitCode);

	if (!ExitCode)
	{
		/* We're out, something went wrong. */

		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		HcClose(hThread);

		HcFree(FileBuffer);
		return FALSE;
	}

	/* Done.*/
	HcClose(hThread);
	HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);

	HcFree(FileBuffer);
	return TRUE;
}

BOOLEAN
HCAPI
HcProcessSuspend(SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	Status = HcSuspendProcess(hProcess);

	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

BOOLEAN
HCAPI
HcProcessSuspendEx(HANDLE hProcess)
{
	return NT_SUCCESS(HcSuspendProcess(hProcess));
}

BOOLEAN
HCAPI
HcProcessResume(SIZE_T dwProcessId)
{
	NTSTATUS Status;
	HANDLE hProcess;

	hProcess = HcProcessOpen(dwProcessId, PROCESS_ALL_ACCESS);

	Status = HcResumeProcess(hProcess);

	HcClose(hProcess);
	return NT_SUCCESS(Status);
}

BOOLEAN
HCAPI
HcProcessResumeEx(HANDLE hProcess)
{
	return NT_SUCCESS(HcResumeProcess(hProcess));
}

BOOLEAN
HCAPI
HcProcessWriteMemory(HANDLE hProcess,
	LPVOID lpBaseAddress,
	CONST VOID* lpBuffer,
	SIZE_T nSize,
	PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue;
	SIZE_T RegionSize;
	PVOID Base;
	BOOLEAN UnProtect;

	/* Set parameters for protect call */
	RegionSize = nSize;
	Base = lpBaseAddress;

	/* Check the current status */
	Status = HcProtectVirtualMemory(hProcess,
		&Base,
		&RegionSize,
		PAGE_EXECUTE_READWRITE,
		&OldValue);

	SetLastError(RtlNtStatusToDosError(Status));
	if (NT_SUCCESS(Status))
	{
		/* Check if we are unprotecting */
		UnProtect = OldValue & (PAGE_READWRITE |
			PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE |
			PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;

		if (!UnProtect)
		{
			/* Set the new protection */
			HcProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Write the memory */
			Status = HcWriteVirtualMemory(hProcess,
				lpBaseAddress,
				(LPVOID)lpBuffer,
				nSize,
				&nSize);

			/* In Win32, the parameter is optional, so handle this case */
			if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

			if (!NT_SUCCESS(Status))
			{
				SetLastError(RtlNtStatusToDosError(Status));
				return FALSE;
			}

			/* Flush the ITLB */
			HcFlushInstructionCache(hProcess, lpBaseAddress, nSize);
			return TRUE;
		}

		/* Check if we were read only */
		if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
		{
			/* Restore protection and fail */
			HcProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Note: This is what Windows returns and code depends on it */
			return FALSE;
		}

		/* Otherwise, do the write */
		Status = HcWriteVirtualMemory(hProcess,
			lpBaseAddress,
			(LPVOID)lpBuffer,
			nSize,
			&nSize);

		/* In Win32, the parameter is optional, so handle this case */
		if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

		/* And restore the protection */
		HcProtectVirtualMemory(hProcess,
			&Base,
			&RegionSize,
			OldValue,
			&OldValue);

		if (!NT_SUCCESS(Status))
		{
			/* Note: This is what Windows returns and code depends on it */
			return FALSE;
		}

		/* Flush the ITLB */
		HcFlushInstructionCache(hProcess, lpBaseAddress, nSize);
		return TRUE;
	}

	return FALSE;
}

BOOLEAN
HCAPI
HcProcessReadMemory(IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	IN LPVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesRead)
{
	NTSTATUS Status;

	/* Do the read */
	Status = HcReadVirtualMemory(hProcess,
		(PVOID)lpBaseAddress,
		lpBuffer,
		nSize,
		&nSize);

	/* In user-mode, this parameter is optional */
	if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;

	if (!NT_SUCCESS(Status))
	{
		/* We failed */
		return FALSE;
	}

	/* Return success */
	return TRUE;
}

HANDLE
HCAPI
HcProcessCreateThread(IN HANDLE hProcess,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParamater,
	IN DWORD dwCreationFlags)
{
	NTSTATUS Status;
	HANDLE hThread = 0;

	Status = HcCreateThreadEx(&hThread,
		THREAD_ALL_ACCESS, 
		NULL, 
		hProcess,
		lpStartAddress,
		lpParamater, 
		dwCreationFlags,
		0,
		0,
		0,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return 0;
	}

	return hThread;
}

BOOLEAN
HCAPI
HcProcessQueryInformationWindow(_In_ HANDLE ProcessHandle,
	PHC_WINDOW_INFORMATION HCWindowInformation)
{
	NTSTATUS Status;
	PVOID Buffer;
	ULONG ReturnLength;
	PPROCESS_WINDOW_INFORMATION WindowInformation;

	/* Query the length. */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessWindowInformation,
		NULL,
		0,
		&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	Buffer = HcAlloc(ReturnLength);

	WindowInformation = (PPROCESS_WINDOW_INFORMATION)Buffer;

	/* Get the window information. */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessWindowInformation,
		WindowInformation,
		ReturnLength,
		&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		HCWindowInformation->WindowFlags = WindowInformation->WindowFlags;

		/* Copy the window's title. */
		wcsncpy(HCWindowInformation->WindowTitle,
			WindowInformation->WindowTitle,
			WindowInformation->WindowTitleLength);

		HcFree(Buffer);
		return TRUE;
	}

	HcFree(Buffer);
	return FALSE;
}

BOOLEAN
HCAPI
HcProcessReadNullifiedString(HANDLE hProcess,
	PUNICODE_STRING usStringIn,
	LPWSTR lpStringOut,
	SIZE_T lpSize)
{
	SIZE_T Len;

	/* Get the maximum len we have/can write in given size */
	Len = usStringIn->Length + sizeof(UNICODE_NULL);
	if (lpSize * sizeof(WCHAR) < Len)
	{
		Len = lpSize * sizeof(WCHAR);
	}

	/* Read the string */
	if (!HcProcessReadMemory(hProcess,
		usStringIn->Buffer,
		lpStringOut,
		Len,
		NULL))
	{
		return FALSE;
	}

	/* If we are at the end of the string, prepare to override to nullify string */
	if (Len == usStringIn->Length + sizeof(UNICODE_NULL))
	{
		Len -= sizeof(UNICODE_NULL);
	}

	/* Nullify at the end if needed */
	if (Len >= lpSize * sizeof(WCHAR))
	{
		if (lpSize)
		{
			ASSERT(lpSize >= sizeof(UNICODE_NULL));
			lpStringOut[lpSize - 1] = UNICODE_NULL;
		}
	}
	/* Otherwise, nullify at last writen char */
	else
	{
		ASSERT(Len + sizeof(UNICODE_NULL) <= lpSize * sizeof(WCHAR));
		lpStringOut[Len / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return TRUE;
}

BOOLEAN
HCAPI
HcProcessLdrModuleToHighCallModule(IN HANDLE hProcess,
	IN PLDR_DATA_TABLE_ENTRY Module,
	OUT PHC_MODULE_INFORMATION phcModuleOut)
{
	/* Copy the modules name from the process. */
	if (!HcProcessReadNullifiedString(hProcess,
		&Module->BaseModuleName,
		phcModuleOut->Name,
		Module->BaseModuleName.Length))
	{
		return FALSE;
	}

	/* Copy the module's path from the process. */
	if (!HcProcessReadNullifiedString(hProcess,
		&Module->FullModuleName,
		phcModuleOut->Path,
		Module->FullModuleName.Length))
	{
		return FALSE;
	}

	phcModuleOut->Size = Module->SizeOfImage;
	phcModuleOut->Base = (SIZE_T)Module->ModuleBase;

	return TRUE;
}

BOOLEAN
HCAPI
HcProcessQueryInformationModule(IN HANDLE hProcess,
	IN HMODULE hModule OPTIONAL,
	OUT PHC_MODULE_INFORMATION phcModuleOut)
{
	SIZE_T Count;
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY Module;
	ULONG Len;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	/* If no module was provided, get base as module */
	if (hModule == NULL)
	{
		if (!HcProcessReadMemory(hProcess,
			&(ProcInfo.PebBaseAddress->ImageBaseAddress),
			&hModule,
			sizeof(hModule),
			NULL))
		{
			return FALSE;
		}
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData,
		sizeof(LoaderData),
		NULL))
	{
	return FALSE;
	}

	if (LoaderData == NULL)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	/* Store list head address */
	ListHead = &(LoaderData->InMemoryOrderModuleList);

	/* Read first element in the modules list */
	if (!HcProcessReadMemory(hProcess,
		&(LoaderData->InMemoryOrderModuleList.Flink),
		&ListEntry,
		sizeof(ListEntry),
		NULL))
	{
		return FALSE;
	}

	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
			&Module,
			sizeof(Module),
			NULL))
		{
			return FALSE;
		}

		/* Does that match the module we're looking for? */
		if (Module.ModuleBase == hModule)
		{
			return HcProcessLdrModuleToHighCallModule(hProcess,
				&Module,
				phcModuleOut);
		}

		++Count;
		if (Count > MAX_MODULES)
		{
			break;
		}

		/* Get to next listed module */
		ListEntry = Module.InMemoryOrderLinks.Flink;
	}

	SetLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

BOOLEAN
HCAPI
HcProcessEnumModules(HANDLE hProcess,
	HC_MODULE_CALLBACK_EVENT hcmCallback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY ldrModule;
	PHC_MODULE_INFORMATION Module;
	SIZE_T Count;
	ULONG Len;

	/* Query the process information to get its PEB address */
	Status = HcQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&ProcInfo,
		sizeof(ProcInfo),
		&Len);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	if (ProcInfo.PebBaseAddress == NULL)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_PARTIAL_COPY));
		return FALSE;
	}

	/* Read loader data address from PEB */
	if (!HcProcessReadMemory(hProcess,
		&(ProcInfo.PebBaseAddress->LoaderData),
		&LoaderData, sizeof(LoaderData),
		NULL))
	{
		return FALSE;
	}

	/* Store list head address */
	ListHead = &LoaderData->InLoadOrderModuleList;

	/* Read first element in the modules list */
	if (!HcProcessReadMemory(hProcess,
		&(LoaderData->InLoadOrderModuleList.Flink),
		&ListEntry,
		sizeof(ListEntry),
		NULL))
	{
		return FALSE;
	}

	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		if (!HcProcessReadMemory(hProcess,
			CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
			&ldrModule,
			sizeof(ldrModule),
			NULL))
		{
			return FALSE;
		}

		InitializeModuleInformation(Module, MAX_PATH, MAX_PATH);

		/* Attempt to convert to a HC module */
		if (HcProcessLdrModuleToHighCallModule(hProcess,
			&ldrModule,
			Module))
		{
			/* Give it to the caller */
			if (hcmCallback(*Module, lParam))
			{
				DestroyModuleInformation(Module);
				return TRUE;
			}

			Count += 1;
		}

		DestroyModuleInformation(Module);

		if (Count > MAX_MODULES)
		{
			SetLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}

		/* Get to next listed module */
		ListEntry = ldrModule.InLoadOrderLinks.Flink;
	}

	return FALSE;
}

BOOLEAN
HCAPI 
HcProcessEnumModulesEx(
	_In_ HANDLE ProcessHandle,
	HC_MODULE_CALLBACK_EVENT hcmCallback,
	LPARAM lParam)
{
	BOOLEAN querySucceeded;
	PVOID baseAddress;
	MEMORY_BASIC_INFORMATION basicInfo;
	PHC_MODULE_INFORMATION hcmInformation;
	SIZE_T allocationSize;

	baseAddress = (PVOID)0;

	if (!NT_SUCCESS(HcQueryVirtualMemory(
		ProcessHandle,
		baseAddress,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL
	)))
	{
		return FALSE;
	}

	querySucceeded = TRUE;

	while (querySucceeded)
	{
		if (basicInfo.Type == MEM_IMAGE)
		{
			InitializeModuleInformation(hcmInformation, MAX_PATH, MAX_PATH);

			hcmInformation->Base = (SIZE_T) basicInfo.AllocationBase;
			allocationSize = 0;

			/* Find next module */
			do
			{
				baseAddress = (PVOID)((ULONG_PTR)baseAddress + basicInfo.RegionSize);
				allocationSize += basicInfo.RegionSize;

				if (!NT_SUCCESS(HcQueryVirtualMemory(
					ProcessHandle,
					baseAddress,
					MemoryBasicInformation,
					&basicInfo,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL)))
				{
					querySucceeded = FALSE;
					break;
				}

			} while (basicInfo.AllocationBase == (PVOID) hcmInformation->Base);

			hcmInformation->Size = allocationSize;

			if (HcProcessModuleFileName(ProcessHandle,
				(PVOID)hcmInformation->Base,
				hcmInformation->Path,
				MAX_PATH))
			{
				/* temporary */
				wcsncpy(hcmInformation->Name, hcmInformation->Path, MAX_PATH);
			}

			if (hcmCallback(*hcmInformation, lParam))
			{
				DestroyModuleInformation(hcmInformation);
				return TRUE;
			}

			DestroyModuleInformation(hcmInformation);
		}
		else
		{
			baseAddress = (PVOID)((ULONG_PTR)baseAddress + basicInfo.RegionSize);

			if (!NT_SUCCESS(HcQueryVirtualMemory(
				ProcessHandle,
				baseAddress,
				MemoryBasicInformation,
				&basicInfo,
				sizeof(MEMORY_BASIC_INFORMATION),
				NULL
			)))
			{
				querySucceeded = FALSE;
			}
		}
	}

	return TRUE;
}

static 
ULONG 
HCAPI 
HcGetProcessListSize()
{
	NTSTATUS Status;
	ULONG Size = MAXSHORT;
	PSYSTEM_PROCESS_INFORMATION ProcInfoArray;

	/* Loop on it */
	while (TRUE)
	{
		/* Allocate for first test */
		if (!(ProcInfoArray = (PSYSTEM_PROCESS_INFORMATION)
			HcAlloc(Size)))
		{
			return FALSE;
		}

		Status = HcQuerySystemInformation(SystemProcessInformation,
			ProcInfoArray,
			Size,
			NULL);

		/* Release, we're only looking for the size. */
		HcFree(ProcInfoArray);

		/* Not enough, go for it again. */
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			Size += MAXSHORT;
			continue;
		}

		break;

	}

	return Size;
}

BOOLEAN
HCAPI
HcProcessQueryByName(LPCWSTR lpProcessName,
	HC_PROCESS_CALLBACK_EVENT hcpCallback,
	LPARAM lParam)
{
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION processInfo;
	HANDLE CurrentHandle;
	PHC_PROCESS_INFORMATION hcpInformation;
	UNICODE_STRING processName;
	PVOID Buffer;
	ULONG Length;

	/* Initialize the unicode string */
	RtlInitUnicodeString(&processName, lpProcessName);

	/* Query the required size. */
	Length = HcGetProcessListSize();

	if (!Length)
	{
		return FALSE;
	}

	/* Allocate the buffer with specified size. */
	if (!(Buffer = HcAlloc(Length)))
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES));
		return FALSE;
	}

	processInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	/* Query the process list. */
	if (!NT_SUCCESS(Status = HcQuerySystemInformation(SystemProcessInformation,
		processInfo,
		Length,
		&Length)))
	{
		HcFree(Buffer);
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	RtlInitUnicodeString(&processInfo->ImageName, L"IdleSystem");

	/* Loop through the process list */
	while (TRUE)
	{
		InitializeProcessInformation(hcpInformation, MAX_PATH);

		/* Check for a match */
		if (!lpProcessName ||
			RtlEqualUnicodeString(&processInfo->ImageName,
				&processName,
				TRUE))
		{

			hcpInformation->Id = HandleToUlong(processInfo->UniqueProcessId);

			/* Copy the name */
			wcsncpy(hcpInformation->Name,
				processInfo->ImageName.Buffer,
				processInfo->ImageName.Length);

			/* Try opening the process */
			if ((CurrentHandle = HcProcessOpen((SIZE_T)processInfo->UniqueProcessId,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)))
			{
				hcpInformation->CanAccess = TRUE;

				/* Query main module */
				HcProcessQueryInformationModule(CurrentHandle,
					NULL,
					hcpInformation->MainModule);

				HcProcessQueryInformationWindow(CurrentHandle,
					hcpInformation->MainWindow);

				/* Close this handle. */
				HcClose(CurrentHandle);
			}

			/* Call the callback as long as the user doesn't return FALSE. */
			if (hcpCallback(*hcpInformation, lParam))
			{
				HcFree(Buffer);
				DestroyProcessInformation(hcpInformation);
				return TRUE;
			}
		}

		DestroyProcessInformation(hcpInformation);

		if (!processInfo->NextEntryOffset)
		{
			break;
		}

		/* Calculate the next entry address */
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + processInfo->NextEntryOffset);
	}

	HcFree(Buffer);
	return FALSE;
}

SIZE_T
WINAPI
HcProcessModuleFileName(HANDLE hProcess,
	LPVOID lpv,
	LPWSTR lpFilename,
	DWORD nSize)
{
	SIZE_T Len;
	SIZE_T OutSize;
	NTSTATUS Status;

	struct
	{
		MEMORY_SECTION_NAME memSection;
		WCHAR CharBuffer[MAX_PATH];
	} SectionName;

	/* If no buffer, no need to keep going on */
	if (nSize == 0)
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	/* Query section name */
	Status = HcQueryVirtualMemory(hProcess, lpv, MemoryMappedFilenameInformation,
		&SectionName, sizeof(SectionName), &OutSize);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return 0;
	}

	/* Prepare to copy file name */
	Len = OutSize = SectionName.memSection.SectionFileName.Length / sizeof(WCHAR);
	if (OutSize + 1 > nSize)
	{
		Len = nSize - 1;
		OutSize = nSize;
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	}
	else
	{
		SetLastError(ERROR_SUCCESS);
	}

	/* Copy, zero and return */
	memcpy(lpFilename, SectionName.memSection.SectionFileName.Buffer, Len * sizeof(WCHAR));
	lpFilename[Len] = 0;

	return OutSize;
}

BOOLEAN
HCAPI
HcProcessSetPrivilegeA(HANDLE hProcess,
	LPCSTR Privilege, 
	BOOLEAN bEnablePrivilege 
){
	NTSTATUS Status;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	PLUID pLuid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	/* Acquire handle to token */
	Status = HcOpenProcessToken(hProcess, 
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
		&hToken);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	/* Find the privilege */
	pLuid = HcLookupPrivilegeValueA(Privilege);
	if (!pLuid)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		HcObjectClose(hToken);
		return FALSE;
	}

	/* Set one privilege */
	tp.PrivilegeCount = 1;

	/* The id of our privilege */
	tp.Privileges[0].Luid = *pLuid;

	/* No special attributes */
	tp.Privileges[0].Attributes = 0;

	Status = HcAdjustPrivilegesToken(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		HcObjectClose(hToken);
		return FALSE;
	}

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = *pLuid;

	if (bEnablePrivilege)
	{
		/* Enable this privilege */
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else 
	{
		/* Disable this privilege */
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	Status = HcAdjustPrivilegesToken(hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		HcObjectClose(hToken);
		return FALSE;
	}

	HcObjectClose(hToken);
	return TRUE;
};

BOOLEAN
HCAPI
HcProcessSetPrivilegeW(HANDLE hProcess,
	LPCWSTR Privilege,
	BOOLEAN bEnablePrivilege
) {
	NTSTATUS Status;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	PLUID pLuid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	/* Acquire handle to token */
	Status = HcOpenProcessToken(hProcess,
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		return FALSE;
	}

	/* Find the privilege */
	pLuid = HcLookupPrivilegeValueW(Privilege);
	if (!pLuid)
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		HcObjectClose(hToken);
		return FALSE;
	}

	/* Set one privilege */
	tp.PrivilegeCount = 1;

	/* The id of our privilege */
	tp.Privileges[0].Luid = *pLuid;

	/* No special attributes */
	tp.Privileges[0].Attributes = 0;

	Status = HcAdjustPrivilegesToken(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		HcObjectClose(hToken);
		return FALSE;
	}

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = *pLuid;

	if (bEnablePrivilege)
	{
		/* Enable this privilege */
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else
	{
		/* Disable this privilege */
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	Status = HcAdjustPrivilegesToken(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(Status))
	{
		SetLastError(RtlNtStatusToDosError(Status));
		HcObjectClose(hToken);
		return FALSE;
	}

	HcObjectClose(hToken);
	return TRUE;
};