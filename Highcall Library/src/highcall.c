#include "../include/highcall.h"
#include "../include/hcsyscall.h"
#include "../include/hcimport.h"
#include "../include/hctrampoline.h"
#include "../include/hcmodule.h"
#include "../include/hcstring.h"
#include "../include/hcprocess.h"
#include "../include/hcapi.h"

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
t_BaseFormatObjectAttributes BaseFormatObjectAttributes;

static HIGHCALL_STATUS HCAPI HcInitializeImports(VOID)
{
	RtlGetVersion = (t_RtlGetVersion)HcModuleProcedureAddressA(NTDLL, "RtlGetVersion");
	if (!RtlGetVersion)
	{
		return HIGHCALL_RTLGETVERSION_UNDEFINED;
	}

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

	BaseFormatObjectAttributes = (t_BaseFormatObjectAttributes)HcModuleProcedureAddressA(KERNEL32,
		"BaseFormatObjectAttributes");

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
	sciCreateThreadEx;


static HIGHCALL_STATUS HcInitializeSyscalls(VOID)
{
	sciQueryInformationToken = HcSyscallIndexA("NtQueryInformationToken");

	if (!(sciOpenProcessToken = HcSyscallIndexA("NtOpenProcessToken")))
	{
		return HIGHCALL_OPENPROCESSTOKEN_UNDEFINED;
	}

	sciResumeProcess = HcSyscallIndexA("NtResumeProcess");
	sciSuspendProcess = HcSyscallIndexA("NtSuspendProcess");
	sciAllocateVirtualMemory = HcSyscallIndexA("NtAllocateVirtualMemory");
	sciFreeVirtualMemory = HcSyscallIndexA("NtFreeVirtualMemory");
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
	sciClose = HcSyscallIndexA("NtClose");
	sciQueryVirtualMemory = HcSyscallIndexA("NtQueryVirtualMemory");
	sciAdjustPrivilegesToken = HcSyscallIndexA("NtAdjustPrivilegesToken");
	sciSetInformationThread = HcSyscallIndexA("NtSetInformationThread");
	sciOpenDirectoryObject = HcSyscallIndexA("NtOpenDirectoryObject");
	sciCreateThreadEx = HcSyscallIndexA("NtCreateThreadEx");

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
		HcGetTokenIsElevated(hToken, &HcGlobalElevated);
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

#pragma region Init Module

HMODULE NTDLL;
HMODULE USER32;
HMODULE KERNEL32;
SIZE_T BaseThreadInit;

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
		if (HcStringEqualW(L"user32.dll", pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			USER32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringEqualW(L"ntdll.dll", pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			NTDLL = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringEqualW(L"kernel32.dll", pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			KERNEL32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	if (!NTDLL)
	{
		return HIGHCALL_FAILED;
	}

	BaseThreadInit = HcModuleProcedureAddressA(KERNEL32, "BaseThreadInitThunk");

	return HIGHCALL_SUCCESS;
}

#pragma endregion

HIGHCALL_STATUS HCAPI HcInitialize()
{
	HIGHCALL_STATUS Status;

	Status = HcInitializeModules();

	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	Status = HcInitializeImports();

	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	Status = HcInitializeSyscalls();

	if (!HIGHCALL_ADVANCE(Status))
	{
		return Status;
	}

	if (!USER32)
	{
		USER32 = HcModuleLoadA("user32.dll");
	}

	HcInitializeTrampoline();
	HcInitializeSecurity();
	HcInitializeWindowsVersion();

	return HIGHCALL_SUCCESS;
}