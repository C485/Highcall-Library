#pragma once
#include "native.h"
#include "hcdef.h"


BOOL
HCAPI
HcStringIsBad(LPCSTR lpcStr);

BOOL
HCAPI
HcStringIsBad(LPCWSTR lpcStr);

LPSTR*
HCAPI
HcStringSplit(LPSTR lpStr, const char cDelimiter, PSIZE_T pdwCount);

VOID
HCAPI
HcStringSplitToIntArray(LPSTR lpStr, const char delim, int* pArray, PSIZE_T dwCount);

VOID
HCAPI
HcStringIntToStringArray(int pIntArray[], SIZE_T dwCountToRead, LPSTR* lpOutStringArray);

VOID
HCAPI
HcStringSubtract(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T dwIndex, SIZE_T dwEndIndex, size_t lpSize = 256);

SIZE_T
HCAPI
HcStringCharIndex(LPCSTR lpStr, char delim);

LPCSTR
HCAPI
HcStringTime();

VOID
HCAPI
HcStringToLower(LPSTR lpStr);

VOID
HCAPI
HcStringToLower(LPWSTR lpStr);

VOID
HCAPI
HcStringToUpper(LPSTR lpStr);

VOID
HCAPI
HcStringToUpper(LPWSTR lpStr);

BOOL
HCAPI
HcStringEqual(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);

BOOL
HCAPI
HcStringEqual(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);
