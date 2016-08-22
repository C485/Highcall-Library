#include "../include/highcall.h"

#pragma region Init Trampoline

tGetWindowThreadProcessId HcGetWindowThreadProcessId;
tGetCursorPos HcGetCursorPos;
tPostMessageA HcPostMessageA;
tPostMessageW HcPostMessageW;
tSendMessageA HcSendMessageA;
tSendMessageW HcSendMessageW;
tCreateRemoteThread HcCreateRemoteThread;
tEnumWindows HcEnumWindows;

static VOID HCAPI HcInitializeTrampoline(VOID)
{
	HcGetWindowThreadProcessId = (tGetWindowThreadProcessId)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32,
		"GetWindowThreadProcessId"), 5);

	HcGetCursorPos = (tGetCursorPos)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32, 
		"GetCursorPos"), 5);

	HcPostMessageA = (tPostMessageA)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32,
		"PostMessageA"), 5);

	HcPostMessageW = (tPostMessageW)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32, 
		"PostMessageW"), 5);

	HcSendMessageA = (tSendMessageA)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32,
		"SendMessageA"), 5);

	HcSendMessageW = (tSendMessageW)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32, 
		"SendMessageW"), 5);

	HcCreateRemoteThread = (tCreateRemoteThread)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(KERNEL32, 
		"CreateRemoteThread"), 5);

	HcEnumWindows = (tEnumWindows)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddressA(USER32,
		"EnumWindows"), 5);
}

#pragma endregion

#pragma region Init Import

t_RtlGetVersion RtlGetVersion;
t_RtlEqualUnicodeString RtlEqualUnicodeString;
t_RtlInitUnicodeString RtlInitUnicodeString;
t_LdrLoadDll LdrLoadDll;
t_RtlAllocateActivationContextStack RtlAllocateActivationContextStack;
t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext;
t_RtlFreeActivationContextStack RtlFreeActivationContextStack;
t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack;
t_RtlActivateActivationContextEx RtlActivateActivationContextEx;
t_RtlNtStatusToDosError RtlNtStatusToDosError;
t_RtlAcquirePebLock RtlAcquirePebLock;
t_RtlReleasePebLock RtlReleasePebLock;

static HIGHCALL_STATUS HCAPI HcInitializeImports(VOID)
{
	RtlEqualUnicodeString = (t_RtlEqualUnicodeString)HcModuleProcedureAddressA(NTDLL,
		"RtlEqualUnicodeString");

	RtlInitUnicodeString = (t_RtlInitUnicodeString)HcModuleProcedureAddressA(NTDLL,
		"RtlInitUnicodeString");

	LdrLoadDll = (t_LdrLoadDll)HcModuleProcedureAddressA(NTDLL,
		"LdrLoadDll");

	RtlAllocateActivationContextStack = (t_RtlAllocateActivationContextStack)HcModuleProcedureAddressA(NTDLL, 
		"RtlAllocateActivationContextStack");

	RtlQueryInformationActivationContext = (t_RtlQueryInformationActivationContext)HcModuleProcedureAddressA(NTDLL, 
		"RtlQueryInformationActivationContext");

	RtlFreeActivationContextStack = (t_RtlFreeActivationContextStack)HcModuleProcedureAddressA(NTDLL,
		"RtlFreeActivationContextStack");

	RtlFreeThreadActivationContextStack = (t_RtlFreeThreadActivationContextStack)HcModuleProcedureAddressA(NTDLL,
		"RtlFreeThreadActivationContextStack");

	RtlActivateActivationContextEx = (t_RtlActivateActivationContextEx)HcModuleProcedureAddressA(NTDLL,
		"RtlActivateActivationContextEx");

	RtlNtStatusToDosError = (t_RtlNtStatusToDosError)HcModuleProcedureAddressA(NTDLL,
		"RtlNtStatusToDosError");

	RtlAcquirePebLock = (t_RtlAcquirePebLock)HcModuleProcedureAddressA(NTDLL,
		"RtlAcquirePebLock");

	RtlReleasePebLock = (t_RtlReleasePebLock)HcModuleProcedureAddressA(NTDLL,
		"RtlReleasePebLock");

	return HIGHCALL_SUCCESS;
}

#pragma endregion

#pragma region Init Syscall

SyscallIndex sciQueryInformationToken,
	sciOpenProcessToken,
	sciResumeProcess,
	sciSuspendProcess,
	sciAllocateVirtualMemory,
	sciFreeVirtualMemory,
	sciResumeThread,
	sciQueryInformationThread,
	sciCreateThread,
	sciFlushInstructionCache,
	sciOpenProcess,
	sciProtectVirtualMemory,
	sciReadVirtualMemory,
	sciWriteVirtualMemory,
	sciQueryInformationProcess,
	sciQuerySystemInformation,
	sciClose,
	sciQueryVirtualMemory,
	sciAdjustPrivilegesToken,
	sciSetInformationThread,
	sciOpenDirectoryObject,
	sciCreateThreadEx,
	sciWaitForSingleObject,
	sciWaitForMultipleObjects,
	sciLockVirtualMemory,
	sciUnlockVirtualMemory;

static HIGHCALL_STATUS HcInitializeMandatorySyscall(VOID)
{
	/* NtClose 0x00c 0x00d 0x00e 0x00f */
	/* NtAllocateVirtualMemory 0x0015 0x0016 0x0017 0x0018 */
	/* NtFreeVirtualMemory 0x001b 0x001c 0x001d 0x001e*/

	/* Set some mandatory syscall identifiers. */
	switch (HcGlobalWindowsVersion)
	{
	case WINDOWS_7:
		sciClose = 0xc;
		sciFreeVirtualMemory = 0x1b;
		sciAllocateVirtualMemory = 0x15;
		break;
	case WINDOWS_8:
		sciClose = 0xd;
		sciFreeVirtualMemory = 0x1c;
		sciAllocateVirtualMemory = 0x16;
		break;
	case WINDOWS_8_1:
		sciClose = 0xe;
		sciFreeVirtualMemory = 0x1d;
		sciAllocateVirtualMemory = 0x17;
		break;
	case WINDOWS_10:
		sciClose = 0xf;
		sciFreeVirtualMemory = 0x1e;
		sciAllocateVirtualMemory = 0x18;
		break;
	default:
		return HIGHCALL_WINDOWS_UNDEFINED;
	}

	return HIGHCALL_SUCCESS;
}

static HIGHCALL_STATUS HcInitializeSyscalls(VOID)
{
	if (!(sciOpenProcessToken = HcSyscallIndexA("NtOpenProcessToken")))
	{
		return HIGHCALL_OPENPROCESSTOKEN_UNDEFINED;
	}

	sciQueryInformationToken = HcSyscallIndexA("NtQueryInformationToken");
	sciResumeProcess = HcSyscallIndexA("NtResumeProcess");
	sciSuspendProcess = HcSyscallIndexA("NtSuspendProcess");
	sciResumeThread = HcSyscallIndexA("NtResumeThread");
	sciQueryInformationThread = HcSyscallIndexA("NtQueryInformationThread");
	sciCreateThread = HcSyscallIndexA("NtCreateThread");
	sciFlushInstructionCache = HcSyscallIndexA("NtFlushInstructionCache");
	sciOpenProcess = HcSyscallIndexA("NtOpenProcess");
	sciProtectVirtualMemory = HcSyscallIndexA("NtProtectVirtualMemory");
	sciReadVirtualMemory = HcSyscallIndexA("NtReadVirtualMemory");
	sciWriteVirtualMemory = HcSyscallIndexA("NtWriteVirtualMemory");
	sciQueryInformationProcess = HcSyscallIndexA("NtQueryInformationProcess");
	sciQuerySystemInformation = HcSyscallIndexA("NtQuerySystemInformation");
	sciQueryVirtualMemory = HcSyscallIndexA("NtQueryVirtualMemory");
	sciAdjustPrivilegesToken = HcSyscallIndexA("NtAdjustPrivilegesToken");
	sciSetInformationThread = HcSyscallIndexA("NtSetInformationThread");
	sciOpenDirectoryObject = HcSyscallIndexA("NtOpenDirectoryObject");
	sciCreateThreadEx = HcSyscallIndexA("NtCreateThreadEx");
	sciWaitForSingleObject = HcSyscallIndexA("NtWaitForSingleObject");
	sciWaitForMultipleObjects = HcSyscallIndexA("NtWaitForMultipleObjects");
	sciUnlockVirtualMemory = HcSyscallIndexA("NtUnlockVirtualMemory");
	sciLockVirtualMemory = HcSyscallIndexA("NtLockVirtualMemory");

	return HIGHCALL_SUCCESS;
}

#pragma endregion

#pragma region Init Security

BOOLEAN HcGlobalElevated;
static VOID HcInitializeSecurity(VOID)
{
	HANDLE hToken;

	HcGlobalElevated = FALSE;

	if (NT_SUCCESS(HcOpenProcessToken(NtCurrentProcess,
		TOKEN_QUERY,
		&hToken)))
	{
		HcTokenIsElevated(hToken, &HcGlobalElevated);
	}
}

#pragma endregion

#pragma region Init Windows

ULONG HcGlobalWindowsVersion;
static VOID HcInitializeWindowsVersion(VOID)
{
	RTL_OSVERSIONINFOEXW versionInfo;
	ULONG majorVersion;
	ULONG minorVersion;

	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&versionInfo)))
	{
		HcGlobalWindowsVersion = WINDOWS_NOT_DEFINED;
		return;
	}

	majorVersion = versionInfo.dwMajorVersion;
	minorVersion = versionInfo.dwMinorVersion;

	/* Windows 7 */
	if (majorVersion == 6 && minorVersion == 1)
	{
		HcGlobalWindowsVersion = WINDOWS_7;
	}
	/* Windows 8.0 */
	else if (majorVersion == 6 && minorVersion == 2)
	{
		HcGlobalWindowsVersion = WINDOWS_8;
	}
	/* Windows 8.1 */
	else if (majorVersion == 6 && minorVersion == 3)
	{
		HcGlobalWindowsVersion = WINDOWS_8_1;
	}
	/* Windows 10 */
	else if (majorVersion == 10 && minorVersion == 0)
	{
		HcGlobalWindowsVersion = WINDOWS_10;
	}
	else
	{
		HcGlobalWindowsVersion = WINDOWS_NOT_SUPPORTED;
	}
}

#pragma endregion

/* Avoid using any functions defined in externs. 
	This is for initialization purposes only.
*/

#pragma region Init Module

HMODULE NTDLL;
HMODULE USER32;
HMODULE KERNEL32;

static HIGHCALL_STATUS HcInitializeModules(VOID)
{
	PPEB pPeb = NtCurrentPeb();
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListHead, pListEntry;

	/* Get the module list in load order */
	pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList);

	/* Loop through entry list till we find a match for the module's name */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		/* Important note is that this is strict to the entire name */
		if (!wcscmp(L"user32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			USER32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (!wcscmp(L"ntdll.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			NTDLL = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;

			SIZE_T szModule;
			PIMAGE_EXPORT_DIRECTORY pExports;
			PDWORD pExportNames;
			PDWORD pExportFunctions;
			PWORD pExportOrdinals;
			LPCSTR lpCurrentFunction;

			szModule = (SIZE_T)NTDLL;
			pExports = HcPEGetExportDirectory(NTDLL);

			/* Get the address containg null terminated export names, in ASCII */
			pExportNames = (PDWORD)(pExports->AddressOfNames + szModule);

			/* List through functions */
			for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
			{
				lpCurrentFunction = (LPCSTR)(pExportNames[i] + szModule);
				if (!lpCurrentFunction)
				{
					continue;
				}

				/* Check for a match*/
				if (!strcmp(lpCurrentFunction, "RtlGetVersion"))
				{
					pExportOrdinals = (PWORD)(pExports->AddressOfNameOrdinals + szModule);
					pExportFunctions = (PDWORD)(pExports->AddressOfFunctions + szModule);

					RtlGetVersion = (t_RtlGetVersion)(pExportFunctions[pExportOrdinals[i]] + szModule);
					break;
				}
			}
		}
		else if (!wcscmp(L"kernel32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			KERNEL32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	if (!NTDLL)
	{
		return HIGHCALL_FAILED;
	}

	if (!RtlGetVersion)
	{
		return HIGHCALL_RTLGETVERSION_UNDEFINED;
	}

	return HIGHCALL_SUCCESS;
}

#pragma endregion

HIGHCALL_STATUS HCAPI HcInitialize()
{
	HIGHCALL_STATUS Status;

	/* Mandatory modules */
	Status = HcInitializeModules(); 
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Initialize windows version to identify some mandatory syscall identifiers. */
	HcInitializeWindowsVersion();

	Status = HcInitializeMandatorySyscall();
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Mandatory imports */
	Status = HcInitializeImports();
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Initialize all syscalls */
	Status = HcInitializeSyscalls();
	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	/* Not mandatory, but for trampolines necessary so if undefined, load. */
	if (!USER32)
	{
		USER32 = HcModuleLoadA("user32.dll");
	}

	/* Unnecesary trampolines */
	HcInitializeTrampoline();

	/* Elevation status, unnecesary*/
	HcInitializeSecurity();

	/* Set debug privilege, convenience. */
	HcProcessSetPrivilegeW(NtCurrentProcess, SE_DEBUG_NAME, TRUE);

	return HIGHCALL_SUCCESS;
}