#include "highcall.h"
#include "hcsyscall.h"
#include "hcimport.h"
#include "hctrampoline.h"
#include "hcmodule.h"
#include "hcstring.h"
#include "hcprocess.h"

#pragma region Init Trampoline

tGetWindowThreadProcessId HcGetWindowThreadProcessId;
tGetCursorPos HcGetCursorPos;
tPostMessageA HcPostMessageA;
tPostMessageW HcPostMessageW;
tSendMessageA HcSendMessageA;
tSendMessageW HcSendMessageW;
tCreateRemoteThread HcCreateRemoteThread;

static VOID HCAPI HcInitializeTrampoline(VOID)
{
	HcGetWindowThreadProcessId = (tGetWindowThreadProcessId)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(USER32, "GetWindowThreadProcessId"));
	HcGetCursorPos = (tGetCursorPos)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(USER32, "GetCursorPos"));
	HcPostMessageA = (tPostMessageA)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(USER32, "PostMessageA"));
	HcPostMessageW = (tPostMessageW)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(USER32, "PostMessageW"));
	HcSendMessageA = (tSendMessageA)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(USER32, "SendMessageA"));
	HcSendMessageW = (tSendMessageW)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(USER32, "SendMessageW"));
	HcCreateRemoteThread = (tCreateRemoteThread)HcTrampolineOriginal((PBYTE)HcModuleProcedureAddress(KERNEL32, "CreateRemoteThread"));
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

static HIGHCALL_STATUS HCAPI HcInitializeImports(VOID)
{
	RtlGetVersion = (t_RtlGetVersion)HcModuleProcedureAddress(NTDLL, "RtlGetVersion");
	if (!RtlGetVersion)
	{
		return HIGHCALL_RTLGETVERSION_UNDEFINED;
	}

	RtlEqualUnicodeString = (t_RtlEqualUnicodeString)HcModuleProcedureAddress(NTDLL, "RtlEqualUnicodeString");
	RtlInitUnicodeString = (t_RtlInitUnicodeString)HcModuleProcedureAddress(NTDLL, "RtlInitUnicodeString");
	LdrLoadDll = (t_LdrLoadDll)HcModuleProcedureAddress(NTDLL, "LdrLoadDll");
	RtlAllocateActivationContextStack = (t_RtlAllocateActivationContextStack)HcModuleProcedureAddress(NTDLL, "RtlAllocateActivationContextStack");
	RtlQueryInformationActivationContext = (t_RtlQueryInformationActivationContext)HcModuleProcedureAddress(NTDLL, "RtlQueryInformationActivationContext");
	RtlFreeActivationContextStack = (t_RtlFreeActivationContextStack)HcModuleProcedureAddress(NTDLL, "RtlFreeActivationContextStack");
	RtlFreeThreadActivationContextStack = (t_RtlFreeThreadActivationContextStack)HcModuleProcedureAddress(NTDLL, "RtlFreeThreadActivationContextStack");
	RtlActivateActivationContextEx = (t_RtlActivateActivationContextEx)HcModuleProcedureAddress(NTDLL, "RtlActivateActivationContextEx");

	return HIGHCALL_SUCCESS;
}

#pragma endregion

#pragma region Init Syscall

SyscallIndex sciQueryInformationToken;
SyscallIndex sciOpenProcessToken;
SyscallIndex sciResumeProcess;
SyscallIndex sciSuspendProcess;
SyscallIndex sciAllocateVirtualMemory;
SyscallIndex sciFreeVirtualMemory;
SyscallIndex sciResumeThread;
SyscallIndex sciQueryInformationThread;
SyscallIndex sciCreateThread;
SyscallIndex sciFlushInstructionCache;
SyscallIndex sciOpenProcess;
SyscallIndex sciProtectVirtualMemory;
SyscallIndex sciReadVirtualMemory;
SyscallIndex sciWriteVirtualMemory;
SyscallIndex sciQueryInformationProcess;
SyscallIndex sciQuerySystemInformation;
SyscallIndex sciClose;
SyscallIndex sciQueryVirtualMemory;

static HIGHCALL_STATUS HcInitializeSyscalls(VOID)
{
	sciQueryInformationToken = HcSyscallIndex("NtQueryInformationToken");

	if (!(sciOpenProcessToken = HcSyscallIndex("NtOpenProcessToken")))
	{
		return HIGHCALL_OPENPROCESSTOKEN_UNDEFINED;
	}

	sciResumeProcess = HcSyscallIndex("NtResumeProcess");
	sciSuspendProcess = HcSyscallIndex("NtSuspendProcess");
	sciAllocateVirtualMemory = HcSyscallIndex("NtAllocateVirtualMemory");
	sciFreeVirtualMemory = HcSyscallIndex("NtFreeVirtualMemory");
	sciResumeThread = HcSyscallIndex("NtResumeThread");
	sciQueryInformationThread = HcSyscallIndex("NtQueryInformationThread");
	sciCreateThread = HcSyscallIndex("NtCreateThread");
	sciFlushInstructionCache = HcSyscallIndex("NtFlushInstructionCache");
	sciOpenProcess = HcSyscallIndex("NtOpenProcess");
	sciProtectVirtualMemory = HcSyscallIndex("NtProtectVirtualMemory");
	sciReadVirtualMemory = HcSyscallIndex("NtReadVirtualMemory");
	sciWriteVirtualMemory = HcSyscallIndex("NtWriteVirtualMemory");
	sciQueryInformationProcess = HcSyscallIndex("NtQueryInformationProcess");
	sciQuerySystemInformation = HcSyscallIndex("NtQuerySystemInformation");
	sciClose = HcSyscallIndex("NtClose");
	sciQueryVirtualMemory = HcSyscallIndex("NtQueryVirtualMemory");

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
		if (HcStringEqual(L"user32.dll", pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			USER32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringEqual(L"ntdll.dll", pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			NTDLL = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringEqual(L"kernel32.dll", pLdrDataTableEntry->FullModuleName.Buffer, TRUE))
		{
			KERNEL32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	if (!USER32 || !KERNEL32 || !NTDLL)
	{
		return HIGHCALL_FAILED;
	}

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

	HcInitializeTrampoline();
	HcInitializeSecurity();
	HcInitializeWindowsVersion();

	return HIGHCALL_SUCCESS;
}