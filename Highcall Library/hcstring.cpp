#define _CRT_SECURE_NO_WARNINGS

#include "hcstring.h"
#include <ctime>
#include <stdio.h>

/*
@implemented
*/
BOOL
HCAPI
HcStringIsBad(LPCSTR lpcStr)
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
HcStringIsBad(LPCWSTR lpcStr)
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

	if (HcStringIsBad(lpStr))
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

	Count += LastDelimiter < (lpStr + strlen(lpStr) - 1);
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
	if (HcStringIsBad(lpStr))
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
	if (HcStringIsBad(lpStr))
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
	if (HcStringIsBad(lpStr))
	{
		return -1;
	}

	LPCSTR pch = strrchr(lpStr, delim);
	return pch ? pch - lpStr + 1 : -1;
}

/*
@implemented
@will be reimplmeneted
*/
LPCSTR
HCAPI
HcStringTime()
{
	time_t rawtime;
	time(&rawtime);
	struct tm timeinfo;
	localtime_s(&timeinfo, &rawtime);
	char* buffer = (char*)malloc(80);
	strftime(buffer, 80, "%d-%m-%Y %I:%M:%S", &timeinfo);
	return buffer;
}

/*
@implemented
*/
VOID
HCAPI
HcStringToLower(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
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
HcStringToLower(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
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
HcStringToUpper(LPSTR lpStr)
{
	if (HcStringIsBad(lpStr))
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
HcStringToUpper(LPWSTR lpStr)
{
	if (HcStringIsBad(lpStr))
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
HcStringEqual(LPCSTR lpString1, LPCSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = strlen(lpString1);
	Size2 = strlen(lpString2);

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
		HcStringToLower(lpCopy1);

		lpCopy2 = (LPSTR)VirtualAlloc(0,
			Size2,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		strncpy(lpCopy2, lpString2, Size2);
		HcStringToLower(lpCopy2);

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
HcStringEqual(LPCWSTR lpString1, LPCWSTR lpString2, BOOLEAN CaseInSensitive)
{
	BOOLEAN Return;
	SIZE_T Size1, Size2;
	BOOLEAN bString1, bString2;

	bString1 = HcStringIsBad(lpString1);
	bString2 = HcStringIsBad(lpString2);

	if (bString1 && bString2)
		return TRUE;

	if (!bString1 && bString2)
		return FALSE;

	if (bString1 && !bString2)
		return FALSE;

	Size1 = wcslen(lpString1);
	Size2 = wcslen(lpString2);

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
		HcStringToLower(lpCopy1);

		lpCopy2 = (LPWSTR)VirtualAlloc(0,
			Size2,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		wcsncpy(lpCopy2, lpString2, Size2);
		HcStringToLower(lpCopy2);

		Return = wcscmp(lpCopy1, lpCopy2);

		VirtualFree(lpCopy1, 0, MEM_RELEASE);
		VirtualFree(lpCopy2, 0, MEM_RELEASE);

		return !Return;
	}

	return !wcscmp(lpString1, lpString2);
}