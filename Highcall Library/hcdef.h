#ifndef HC_DEFINE_H
#define HC_DEFINE_H

#include <windows.h>

#define STATUS_INVALID_STRING			(NTSTATUS) 0xC0000500L
#define WINDOWS_7 61
#define WINDOWS_8 62
#define WINDOWS_8_1 63
#define WINDOWS_10 100
#define WINDOWS_NOT_SUPPORTED 0
#define WINDOWS_NOT_DEFINED -1

#define HCAPI __stdcall
#define MAX_INT_STRING (sizeof(char) * 9) + UNICODE_NULL

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

#ifdef __cplusplus
#define HC_GLOBAL extern "C"
#else
#define HC_GLOBAL extern
#endif

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, SIZE_T, LPVOID);

typedef struct _HC_MANUAL_MAP
{
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_MAP, *PHC_MANUAL_MAP;

typedef SIZE_T TrampolineJump;
typedef DWORD SyscallIndex;

typedef struct _HC_MODULE_INFORMATION
{
	SIZE_T		Size;
	SIZE_T		Base;
	LPWSTR		Name;
	LPWSTR		Path;

} HC_MODULE_INFORMATION, *PHC_MODULE_INFORMATION;

#define InitializeModuleInformation(obj, s1, s2) {\
	(obj) = VirtualAlloc(NULL, sizeof(HC_MODULE_INFORMATION), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\
	(obj)->Name = (LPWSTR)VirtualAlloc(NULL, \
		s1, \
		MEM_RESERVE | MEM_COMMIT, \
		PAGE_READWRITE);	\
	(obj)->Path = (LPWSTR)VirtualAlloc(NULL, \
		s2, \
		MEM_RESERVE | MEM_COMMIT, \
		PAGE_READWRITE); \
	(obj)->Size = 0; \
	(obj)->Base = 0; \
}\

#define DestroyModuleInformation(o) {\
	VirtualFree((o)->Name, 0, MEM_RELEASE); \
	VirtualFree((o)->Path, 0, MEM_RELEASE); \
	VirtualFree(o, 0, MEM_RELEASE);\
}\

typedef struct _HC_WINDOW_INFORMATION
{
	LPWSTR WindowTitle;
	ULONG WindowFlags;
	HWND WindowHandle;

} HC_WINDOW_INFORMATION, *PHC_WINDOW_INFORMATION;

#define InitializeWindowInformation(wInfo, s1) {\
	(wInfo) = VirtualAlloc(NULL, sizeof(HC_WINDOW_INFORMATION), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\
	(wInfo)->WindowTitle = (LPWSTR)VirtualAlloc(NULL, \
		s1, \
		MEM_RESERVE | MEM_COMMIT, \
		PAGE_READWRITE);	\
	(wInfo)->WindowFlags = 0; \
	(wInfo)->WindowHandle = 0; \
}\

#define DestroyWindowInformation(o){\
	VirtualFree((o)->WindowTitle, 0, MEM_RELEASE); \
	VirtualFree(o, 0, MEM_RELEASE);\
}\

typedef struct _HC_PROCESS_INFORMATION
{
	DWORD					Id;
	LPWSTR					Name;
	PHC_MODULE_INFORMATION	MainModule;
	PHC_WINDOW_INFORMATION	MainWindow;
	BOOLEAN					CanAccess;

} HC_PROCESS_INFORMATION, *PHC_PROCESS_INFORMATION;

#define InitializeProcessInformation(o, s1){\
	o = VirtualAlloc(NULL, sizeof(HC_PROCESS_INFORMATION), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\
	InitializeModuleInformation(o->MainModule, s1, s1);\
	InitializeWindowInformation(o->MainWindow, s1);\
	(o)->Name = (LPWSTR)VirtualAlloc(NULL, \
		s1, \
		MEM_RESERVE | MEM_COMMIT, \
		PAGE_READWRITE);	\
	(o)->Id = 0; \
	(o)->CanAccess = 0; \
}\

#define DestroyProcessInformation(o) {\
	VirtualFree((o)->Name, 0, MEM_RELEASE); \
	DestroyModuleInformation(o->MainModule);\
	DestroyWindowInformation(o->MainWindow); \
	VirtualFree(o, 0, MEM_RELEASE);\
}\

typedef BOOL(*HC_PROCESS_CALLBACK_EVENT)(HC_PROCESS_INFORMATION hcpInformation, LPARAM lParam);
typedef BOOL(*HC_MODULE_CALLBACK_EVENT)(HC_MODULE_INFORMATION hcmInformation, LPARAM lParam);

typedef struct _mem_result
{
	SIZE_T address;
	BOOL accessible;

	SIZE_T length;
	unsigned char* buffer;

} mem_result;

typedef struct _HC_FILE_INFORMATION
{
	DWORD Size;
	PBYTE Data;

} HC_FILE_INFORMATION, *PHC_FILE_INFORMATION;

#endif