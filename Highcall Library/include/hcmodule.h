#ifndef HC_MODULE_H
#define HC_MODULE_H

#include "hcdef.h"
#include "../native/native.h"

HC_GLOBAL HMODULE NTDLL;
HC_GLOBAL HMODULE USER32;
HC_GLOBAL HMODULE KERNEL32;

#if defined (__cplusplus)
extern "C" {
#endif

	HMODULE
		HCAPI
		HcModuleHandleW(LPCWSTR lpModuleName);

	HMODULE
		HCAPI
		HcModuleHandleA(LPCSTR lpModuleName);

	BOOLEAN
		HCAPI
		HcModuleListExports(HMODULE hModule, HC_EXPORT_LIST_CALLBACK callback, LPARAM lpParam);

	SIZE_T
		HCAPI
		HcModuleProcedureAddressA(HANDLE hModule, LPCSTR lpProcedureName);

	SIZE_T
		HCAPI
		HcModuleProcedureAddressW(HANDLE hModule, LPCWSTR lpProcedureName);

	HMODULE
		HCAPI
		HcModuleLoadA(LPCSTR lpPath);

	HMODULE
		HCAPI
		HcModuleLoadW(LPCWSTR lpPath);

#endif

#if defined (__cplusplus)
}
#endif