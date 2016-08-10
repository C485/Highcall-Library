#pragma once

#define STATUS_INVALID_STRING			(NTSTATUS) 0xC0000500L
#define WINDOWS_7 61
#define WINDOWS_8 62
#define WINDOWS_8_1 63
#define WINDOWS_10 100
#define WINDOWS_NOT_SUPPORTED 0

#define HCAPI __stdcall
#define MAX_INT_STRING (sizeof(char) * 9) + UNICODE_NULL