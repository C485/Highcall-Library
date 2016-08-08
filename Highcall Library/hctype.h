#pragma once


typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;

typedef unsigned int TrampolineJump;

typedef unsigned int SyscallIndex;

typedef struct _HC_MODULE_INFORMATION
{
	DWORD		Size;
	DWORD		Base;
	LPWSTR		Name;
	LPWSTR		Path;

	_HC_MODULE_INFORMATION()
	{
		Name = (LPWSTR)VirtualAlloc(NULL,
			MAX_PATH,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		Path = (LPWSTR)VirtualAlloc(NULL,
			MAX_PATH,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		Size = 0;
		Base = 0;
	}

	~_HC_MODULE_INFORMATION()
	{
		VirtualFree(Name, 0, MEM_RELEASE);
		VirtualFree(Path, 0, MEM_RELEASE);
	}

} HC_MODULE_INFORMATION, *PHC_MODULE_INFORMATION;

typedef struct _HC_WINDOW_INFORMATION
{
	LPWSTR WindowTitle;
	ULONG WindowFlags;
	HWND WindowHandle;

	_HC_WINDOW_INFORMATION()
	{
		WindowTitle = (LPWSTR)VirtualAlloc(NULL,
			MAX_PATH,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		WindowFlags = 0;
		WindowHandle = 0;
	}

	~_HC_WINDOW_INFORMATION()
	{
		VirtualFree(WindowTitle, 0, MEM_RELEASE);
	}

} HC_WINDOW_INFORMATION, *PHC_WINDOW_INFORMATION;

typedef struct _HC_PROCESS_INFORMATION
{
	DWORD					Id;
	LPWSTR					Name;
	HC_MODULE_INFORMATION	MainModule;
	HC_WINDOW_INFORMATION	MainWindow;
	BOOLEAN					CanAccess;

	_HC_PROCESS_INFORMATION()
	{
		Name = (LPWSTR)VirtualAlloc(NULL,
			MAX_PATH,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		Id = 0;
		CanAccess = FALSE;
	}

	~_HC_PROCESS_INFORMATION()
	{
		VirtualFree(Name, 0, MEM_RELEASE);
	}

} HC_PROCESS_INFORMATION, *PHC_PROCESS_INFORMATION;

typedef BOOL(*HC_PROCESS_CALLBACK_EVENT)(HC_PROCESS_INFORMATION hcpInformation, LPARAM lParam);
typedef BOOL(*HC_MODULE_CALLBACK_EVENT)(HC_MODULE_INFORMATION hcmInformation, LPARAM lParam);

typedef struct _mem_result
{
	DWORD address;
	BOOL accessible;

	DWORD length;
	unsigned char* buffer;

} mem_result;