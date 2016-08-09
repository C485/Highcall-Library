#include "import.h"
#include "hcapi.h"
#include "global.h"

static SIZE_T dwRtlGetVersion = HcGetProcedureAddress(NTDLL, "RtlGetVersion");
t_RtlGetVersion RtlGetVersion = (t_RtlGetVersion) dwRtlGetVersion;

static SIZE_T dwRtlEqualUnicodeString = HcGetProcedureAddress(NTDLL, "RtlEqualUnicodeString");
t_RtlEqualUnicodeString RtlEqualUnicodeString = (t_RtlEqualUnicodeString)dwRtlEqualUnicodeString;

static SIZE_T dwRtlInitUnicodeString = HcGetProcedureAddress(NTDLL, "RtlInitUnicodeString");
t_RtlInitUnicodeString RtlInitUnicodeString = (t_RtlInitUnicodeString)dwRtlInitUnicodeString;

static SIZE_T dwLdrLoadDll = HcGetProcedureAddress(NTDLL, "LdrLoadDll");
t_LdrLoadDll LdrLoadDll = (t_LdrLoadDll)dwLdrLoadDll;

static SIZE_T dwRtlAllocateActivationContextStack = HcGetProcedureAddress(NTDLL, "RtlAllocateActivationContextStack");
t_RtlAllocateActivationContextStack RtlAllocateActivationContextStack = (t_RtlAllocateActivationContextStack)dwRtlAllocateActivationContextStack;

static SIZE_T dwRtlQueryInformationActivationContext = HcGetProcedureAddress(NTDLL, "RtlQueryInformationActivationContext");
t_RtlQueryInformationActivationContext RtlQueryInformationActivationContext = (t_RtlQueryInformationActivationContext)dwRtlQueryInformationActivationContext;

static SIZE_T dwRtlFreeActivationContextStack = HcGetProcedureAddress(NTDLL, "RtlFreeActivationContextStack");
t_RtlFreeActivationContextStack RtlFreeActivationContextStack = (t_RtlFreeActivationContextStack)dwRtlFreeActivationContextStack;

static SIZE_T dwRtlFreeThreadActivationContextStack = HcGetProcedureAddress(NTDLL, "RtlFreeThreadActivationContextStack");
t_RtlFreeThreadActivationContextStack RtlFreeThreadActivationContextStack = (t_RtlFreeThreadActivationContextStack)dwRtlFreeThreadActivationContextStack;

static SIZE_T dwRtlActivateActivationContextEx = HcGetProcedureAddress(NTDLL, "RtlActivateActivationContextEx");
t_RtlActivateActivationContextEx RtlActivateActivationContextEx = (t_RtlActivateActivationContextEx)dwRtlActivateActivationContextEx;