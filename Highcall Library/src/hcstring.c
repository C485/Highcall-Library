#define _CRT_SECURE_NO_WARNINGS

#include "../include/hcstring.h"
#include "../include/hcimport.h"
#include <stdio.h>

/*
@implemented
*/
BOOL
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
BOOL
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

	if (!(plpResult = (LPSTR*)VirtualAlloc(NULL,
		sizeof(LPSTR) * Count,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE)))
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
		lpCurrent = (LPSTR)VirtualAlloc(0,
			MAX_INT_STRING,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		__try
		{

			/* Parste the content. */
			sprintf(lpCurrent, "%d", pIntArray[i]);

			/* Terminate the last character. */
			lpCurrent[9] = 0;

			/* move the string into the array */
			strncpy(lpOutStringArray[i], lpCurrent, MAX_INT_STRING);

			VirtualFree(lpCurrent, 0, MEM_RELEASE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			VirtualFree(lpCurrent, 0, MEM_RELEASE);
			SetLastError(STATUS_PARTIAL_COPY);
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

SIZE_T
HCAPI
HcStringSecureLengthA(LPCSTR lpString)
{
	SIZE_T Length;
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

SIZE_T
HCAPI
HcStringSecureLengthW(LPCWSTR lpString)
{
	SIZE_T Length;
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

SIZE_T
HCAPI
HcStringLengthA(LPCSTR lpString)
{
	SIZE_T Length = 0;
	for (; *lpString; *lpString++)
		Length++;
	return Length;
}

SIZE_T
HCAPI
HcStringLengthW(LPCWSTR lpString)
{
	SIZE_T Length = 0;
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
BOOL
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

		lpCopy1 = (LPSTR)VirtualAlloc(0,
			Size1,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		strncpy(lpCopy1, lpString1, Size1);
		HcStringToLowerA(lpCopy1);

		lpCopy2 = (LPSTR)VirtualAlloc(0,
			Size2,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		strncpy(lpCopy2, lpString2, Size2);
		HcStringToLowerA(lpCopy2);

		Return = strcmp(lpCopy1, lpCopy2);

		VirtualFree(lpCopy1, 0, MEM_RELEASE);
		VirtualFree(lpCopy2, 0, MEM_RELEASE);

		return !Return;
	}

	return !strcmp(lpString1, lpString2);
}

/*
@implemented
*/
BOOL
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

		lpCopy1 = (LPWSTR)VirtualAlloc(0,
			Size1,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		wcsncpy(lpCopy1, lpString1, Size1);
		HcStringToLowerW(lpCopy1);

		lpCopy2 = (LPWSTR)VirtualAlloc(0,
			Size2,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		wcsncpy(lpCopy2, lpString2, Size2);
		HcStringToLowerW(lpCopy2);

		Return = wcscmp(lpCopy1, lpCopy2);

		VirtualFree(lpCopy1, 0, MEM_RELEASE);
		VirtualFree(lpCopy2, 0, MEM_RELEASE);

		return !Return;
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

	/* Convert */
	Size = MultiByteToWideChar(CP_ACP, 0, lpStringToConvert, Size, lpStringOut, Size);

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