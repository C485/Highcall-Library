#ifndef HC_TRAMPOLINE_H
#define HC_TRAMPOLINE_H

#include "hcdef.h"

#if defined (__cplusplus)
extern "C" {
#endif

	DWORD HCAPI HcTrampolineCalculateLength(BYTE* Src, DWORD NeededLength);

	PVOID HCAPI HcTrampolineOriginal(PBYTE lpBaseAddress, DWORD dwMinimumSize);

	typedef BOOLEAN(WINAPI* tGetWindowThreadProcessId) (_In_ HWND hWnd, _Out_opt_ LPDWORD lpdwProcessId);
	extern tGetWindowThreadProcessId HcGetWindowThreadProcessId;

	typedef BOOLEAN(WINAPI* tGetCursorPos) (_Out_ LPPOINT lpPoint);
	extern tGetCursorPos HcGetCursorPos;

	typedef BOOLEAN(WINAPI* tPostMessageA) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	extern tPostMessageA HcPostMessageA;

	typedef BOOLEAN(WINAPI* tPostMessageW) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	extern tPostMessageW HcPostMessageW;

	typedef BOOLEAN(WINAPI* tSendMessageA) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	extern tSendMessageA HcSendMessageA;

	typedef BOOLEAN(WINAPI* tSendMessageW) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	extern tSendMessageW HcSendMessageW;

	typedef HANDLE(WINAPI* tCreateRemoteThread) (
		_In_  HANDLE                 hProcess,
		_In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		_In_  SIZE_T                 dwStackSize,
		_In_  LPTHREAD_START_ROUTINE lpStartAddress,
		_In_  LPVOID                 lpParameter,
		_In_  DWORD                  dwCreationFlags,
		_Out_ LPDWORD                lpThreadId
		);
	extern tCreateRemoteThread HcCreateRemoteThread;

	typedef BOOLEAN (WINAPI* tEnumWindows) (_In_ WNDENUMPROC lpEnumFunc,
			_In_ LPARAM lParam);
	extern tEnumWindows HcEnumWindows;

#endif
#if defined (__cplusplus)
}
#endif