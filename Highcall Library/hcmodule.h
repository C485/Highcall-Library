#pragma once
#include "hcdef.h"
#include "native.h"

extern HMODULE NTDLL;
extern HMODULE USER32;
extern HMODULE KERNEL32;

HMODULE
HCAPI
HcModuleHandle(LPCWSTR lpModuleName);

HMODULE
HCAPI
HcModuleHandle(LPCSTR lpModuleName);

SIZE_T
HCAPI
HcModuleProcedureAddress(HANDLE hModule, LPCSTR lpProcedureName);

SIZE_T
HCAPI
HcModuleProcedureAddress(HANDLE hModule, LPCWSTR lpProcedureName);

HMODULE
HCAPI
HcModuleLoad(LPCSTR lpPath);

HMODULE
HCAPI
HcModuleLoad(LPCWSTR lpPath);