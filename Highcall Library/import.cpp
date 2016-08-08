#include "import.h"
#include "hcapi.h"
#include "global.h"

static DWORD dwRtlGetVersion = HcGetProcedureAddress(NTDLL, "RtlGetVersion");
t_RtlGetVersion RtlGetVersion = (t_RtlGetVersion) dwRtlGetVersion;

static DWORD dwRtlEqualUnicodeString = HcGetProcedureAddress(NTDLL, "RtlEqualUnicodeString");
t_RtlEqualUnicodeString RtlEqualUnicodeString = (t_RtlEqualUnicodeString)dwRtlEqualUnicodeString;

static DWORD dwRtlInitUnicodeString = HcGetProcedureAddress(NTDLL, "RtlInitUnicodeString");
t_RtlInitUnicodeString RtlInitUnicodeString = (t_RtlInitUnicodeString)dwRtlInitUnicodeString;

static DWORD dwLdrLoadDll = HcGetProcedureAddress(NTDLL, "LdrLoadDll");
t_LdrLoadDll LdrLoadDll = (t_LdrLoadDll)dwLdrLoadDll;

static DWORD dwRtlAllocateActivationContextStack = HcGetProcedureAddress(NTDLL, "RtlAllocateActivationContextStack");
t_RtlAllocateActivationContextStack RtlAllocateActivationContextStack = (t_RtlAllocateActivationContextStack)dwRtlAllocateActivationContextStack;

static DWORD dwRtlQueryInformationActivationContext = HcGetProcedureAddress(NTDLL, "RtlQueryInformationActivationContext");

t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext = (t_RtlQueryInformationActivationContext)dwRtlQueryInformationActivationContext;

static DWORD dwRtlFreeActivationContextStack = HcGetProcedureAddress(NTDLL, "RtlFreeActivationContextStack");
t_RtlFreeActivationContextStack RtlFreeActivationContextStack = (t_RtlFreeActivationContextStack)dwRtlFreeActivationContextStack;

static DWORD dwRtlFreeThreadActivationContextStack = HcGetProcedureAddress(NTDLL, "RtlFreeThreadActivationContextStack");
t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack = (t_RtlFreeThreadActivationContextStack)dwRtlFreeThreadActivationContextStack;

static DWORD dwRtlActivateActivationContextEx = HcGetProcedureAddress(NTDLL, "RtlActivateActivationContextEx");
t_RtlActivateActivationContextEx RtlActivateActivationContextEx = (t_RtlActivateActivationContextEx)dwRtlActivateActivationContextEx;