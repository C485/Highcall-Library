#pragma once
#include "../native/native.h"
#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	BOOLEAN
		HCAPI
		HcStringIsBadA(LPCSTR lpcStr);

	BOOLEAN
		HCAPI
		HcStringIsBadW(LPCWSTR lpcStr);

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
		HcStringSubtract(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T dwIndex, SIZE_T dwEndIndex, size_t lpSize);

	SIZE_T
		HCAPI
		HcStringCharIndex(LPCSTR lpStr, char delim);

	LPCSTR
		HCAPI
		HcStringTime();

	DWORD
		HCAPI
		HcStringSecureLengthA(LPCSTR lpString);

	DWORD
		HCAPI
		HcStringSecureLengthW(LPCWSTR lpString);

	DWORD
		HCAPI
		HcStringLengthA(LPCSTR lpString);

	DWORD
		HCAPI
		HcStringLengthW(LPCWSTR lpString);

	VOID
		HCAPI
		HcStringToLowerA(LPSTR lpStr);

	VOID
		HCAPI
		HcStringToLowerW(LPWSTR lpStr);

	VOID
		HCAPI
		HcStringToUpperA(LPSTR lpStr);

	VOID
		HCAPI
		HcStringToUpperW(LPWSTR lpStr);

	BOOLEAN
		HCAPI
		HcStringEqualA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive);

	BOOLEAN
		HCAPI
		HcStringEqualW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive);

	BOOLEAN
		HCAPI
		HcStringConvertA(LPCSTR lpStringToConvert,
			LPWSTR lpStringOut,
			DWORD Size);

	BOOLEAN
		HCAPI
		HcStringConvertW(LPCWSTR lpStringToConvert,
			LPSTR lpStringOut,
			DWORD Size);

#if defined (__cplusplus)
}
#endif
