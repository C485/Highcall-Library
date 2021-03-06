#define _CRT_SECURE_NO_WARNINGS

#include "../include/hcstring.h"
#include "../include/hcimport.h"
#include "../include/hcvirtual.h"

#include <stdio.h>

/*
@implemented
*/
BOOLEAN
HCAPI
HcStringIsBadA(LPCSTR lpcStr)
{
	if (!lpcStr)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	__try
	{
		for (; *lpcStr; *lpcStr++)
		{
			if (!*lpcStr)
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	return FALSE;
}

/*
@implemented
*/
BOOLEAN
HCAPI
HcStringIsBadW(LPCWSTR lpcStr)
{
	if (!lpcStr)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	__try
	{
		for (; *lpcStr; *lpcStr++)
		{
			if (!*lpcStr)
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(STATUS_INVALID_STRING);
		return TRUE;
	}

	return FALSE;
}

/*
@implemented
*/
LPSTR*
HCAPI
HcStringSplit(LPSTR lpStr, const char cDelimiter, PSIZE_T pdwCount)
{
	LPSTR* plpResult;
	LPSTR lpCopy;
	LPSTR LastDelimiter;
	LPSTR lpToken;
	SIZE_T Count;
	SIZE_T Index;
	char lpTerminatedDelim[2];

	if (HcStringIsBadA(lpStr))
	{
		return 0;
	}

	/* Set the pointer to the copy. */
	if (!(lpCopy = lpStr))
	{
		return 0;
	}

	Count = 0;
	LastDelimiter = 0;

	/* Null terminate the delimiter. */
	lpTerminatedDelim[0] = cDelimiter;
	lpTerminatedDelim[1] = 0;

	/* Test the copy for the final delimiter location, set the count. */
	while (*lpCopy)
	{
		if (cDelimiter == *lpCopy)
		{
			Count++;
			LastDelimiter = lpCopy;
		}
		lpCopy++;
	}

	Count += LastDelimiter < (lpStr + HcStringLengthA(lpStr) - 1);
	Count++;

	if (!(plpResult = (LPSTR*)HcAlloc(sizeof(LPSTR) * Count)))
	{
		return 0;
	}

	/* Get the first token. */
	lpToken = strtok(lpStr, lpTerminatedDelim);

	Index = 0;
	*pdwCount = 0;

	/* Loop over the splits. */
	while (lpToken)
	{
		ASSERT(Index < Count);

		/* Duplicate the string and insert into return array. */
		*(plpResult + Index++) = _strdup(lpToken);
		*pdwCount += 1;

		/* Acquire next token. */
		lpToken = strtok(0, lpTerminatedDelim);
	}
	ASSERT(Index == Count - 1);

	/* Null terminate final string. */
	*(plpResult + Index) = 0;

	return plpResult;
}

/*
@implemented
*/
VOID
HCAPI
HcStringSplitToIntArray(LPSTR lpStr, const char delim, int* pArray, PSIZE_T dwCount)
{
	LPSTR* plpSplit;
	SIZE_T Count;
	if (HcStringIsBadA(lpStr))
	{
		return;
	}

	/* Acquire the split. */
	plpSplit = HcStringSplit(lpStr, delim, &Count);
	if (!plpSplit)
	{
		return;
	}

	__try
	{
		/* get the length of the array */
		for (SIZE_T i = 0; dwCount; i++)
		{
			pArray[i] = atoi(plpSplit[i]);
			*dwCount += 1;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(STATUS_INFO_LENGTH_MISMATCH);
		return;
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringIntToStringArray(int pIntArray[], SIZE_T dwCountToRead, LPSTR* lpOutStringArray)
{
	LPSTR lpCurrent;

	/* Loop the count. */
	for (SIZE_T i = 0; i < dwCountToRead; i++)
	{
		/* Allocate next. */
		lpCurrent = (LPSTR)HcAlloc(MAX_INT_STRING);
		__try
		{

			/* Parste the content. */
			sprintf(lpCurrent, "%d", pIntArray[i]);

			/* Terminate the last character. */
			lpCurrent[9] = 0;

			/* move the string into the array */
			strncpy(lpOutStringArray[i], lpCurrent, MAX_INT_STRING);

			HcFree(lpCurrent);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			HcFree(lpCurrent);
			SetLastError(RtlNtStatusToDosError(STATUS_PARTIAL_COPY));
			return;
		}
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringSubtract(LPCSTR lpStr, LPSTR lpOutStr, SIZE_T dwIndex, SIZE_T dwEndIndex, size_t lpSize)
{
	if (HcStringIsBadA(lpStr))
	{
		return;
	}

	/* Create the null terminated sub string. */
	if (strncpy(lpOutStr, lpStr + dwIndex, dwEndIndex - dwIndex))
	{
		lpOutStr[dwEndIndex - dwIndex] = ANSI_NULL;
	}
}

SIZE_T
HCAPI
HcStringCharIndex(LPCSTR lpStr, char delim)
{
	if (HcStringIsBadA(lpStr))
	{
		return -1;
	}

	LPCSTR pch = strrchr(lpStr, delim);
	return pch ? pch - lpStr + 1 : -1;
}

/*
@unimplemented
*/
LPCSTR
HCAPI
HcStringTime()
{
	return NULL;
}

DWORD
HCAPI
HcStringSecureLengthA(LPCSTR lpString)
{
	DWORD Length = 0;
	__try
	{
		for (; *lpString; *lpString++)
			Length++;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return Length;
	}
	return Length;
}

DWORD
HCAPI
HcStringSecureLengthW(LPCWSTR lpString)
{
	DWORD Length = 0;
	__try
	{
		for (; *lpString; *lpString++)
			Length++;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return Length;
	}
	return Length;
}

DWORD
HCAPI
HcStringLengthA(LPCSTR lpString)
{
	DWORD Length = 0;
	for (; *lpString; *lpString++)
		Length++;
	return Length;
}

DWORD
HCAPI
HcStringLengthW(LPCWSTR lpString)
{
	DWORD Length = 0;
	for (; *lpString; *lpString++)
		Length++;
	return Length;
}

/*
@implemented
*/
VOID
HCAPI
HcStringToLowerA(LPSTR lpStr)
{
	if (HcStringIsBadA(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = tolower(*lpStr);
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringToLowerW(LPWSTR lpStr)
{
	if (HcStringIsBadW(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = tolower(*lpStr);
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringToUpperA(LPSTR lpStr)
{
	if (HcStringIsBadA(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = toupper(*lpStr);
	}
}

/*
@implemented
*/
VOID
HCAPI
HcStringToUpperW(LPWSTR lpStr)
{
	if (HcStringIsBadW(lpStr))
		return;

	for (; *lpStr; *lpStr++)
	{
		*lpStr = toupper(*lpStr);
	}
}
/*
@implemented
*/
BOOLEAN
HCAPI
HcStringEqualA(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBadA(lpString1);
	bString2 = HcStringIsBadA(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = HcStringLengthA(lpString1);
	Size2 = HcStringLengthA(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPSTR lpCopy1, lpCopy2;

		lpCopy1 = (LPSTR)HcAlloc(Size1);

		strncpy(lpCopy1, lpString1, Size1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = (LPSTR)HcAlloc(Size2);

		strncpy(lpCopy2, lpString2, Size2);
		HcStringToLowerA(lpCopy2);

		Return = strcmp(lpCopy1, lpCopy2) == 0 ? TRUE : FALSE;

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return !strcmp(lpString1, lpString2);
}

/*
@implemented
*/
BOOLEAN
HCAPI
HcStringEqualW(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBadW(lpString1);
	bString2 = HcStringIsBadW(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = HcStringLengthW(lpString1);
	Size2 = HcStringLengthW(lpString2);

	if (Size1 != Size2)
		return FALSE;

	if (CaseInSensitive)
	{
		LPWSTR lpCopy1, lpCopy2;

		lpCopy1 = (LPWSTR)HcAlloc(Size1);

		wcsncpy(lpCopy1, lpString1, Size1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = (LPWSTR)HcAlloc(Size2);

		wcsncpy(lpCopy2, lpString2, Size2);
		HcStringToLowerW(lpCopy2);

		Return = wcscmp(lpCopy1, lpCopy2) == 0 ? TRUE : FALSE;

		HcFree(lpCopy1);
		HcFree(lpCopy2);

		return Return;
	}

	return !wcscmp(lpString1, lpString2);
}

/*
@implemented
*/
BOOLEAN
HCAPI
HcStringConvertA(LPCSTR lpStringToConvert,
	LPWSTR lpStringOut,
	DWORD Size)
{
	if (HcStringIsBadA(lpStringToConvert))
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		return FALSE;
	}
	
	if (!Size)
	{
		return FALSE;
	}

	/* Convert */
	Size = MultiByteToWideChar(CP_UTF8, 0, lpStringToConvert, Size, lpStringOut, Size);
	if (!Size)
	{
		return FALSE;
	}

	return TRUE;
}

/*
@implemented
*/
BOOLEAN
HCAPI
HcStringConvertW(LPCWSTR lpStringToConvert,
	LPSTR lpStringOut,
	DWORD Size)
{
	if (HcStringIsBadW(lpStringToConvert))
	{
		SetLastError(RtlNtStatusToDosError(STATUS_INVALID_PARAMETER));
		return FALSE;
	}

	if (!Size)
	{
		return FALSE;
	}

	/* Convert */
	Size = WideCharToMultiByte(CP_UTF8,
		0, 
		lpStringToConvert,
		-1,
		lpStringOut,
		Size, 
		NULL, 
		NULL);

	if (!Size)
	{
		return FALSE;
	}

	return TRUE;
}