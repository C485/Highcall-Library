#pragma once
#include "hcdef.h"

DWORD HCAPI HcTrampolineCalculateLength(BYTE* Src, DWORD NeededLength);

PBYTE HCAPI HcTrampolineOriginal(PBYTE lpBaseAddress, DWORD dwMinimumSize = 5);

typedef BOOL(WINAPI* tGetWindowThreadProcessId) (_In_ HWND hWnd, _Out_opt_ LPDWORD lpdwProcessId);
extern tGetWindowThreadProcessId HcGetWindowThreadProcessId;

typedef BOOL(WINAPI* tGetCursorPos) (_Out_ LPPOINT lpPoint);
extern tGetCursorPos HcGetCursorPos;

typedef BOOL(WINAPI* tPostMessageA) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
extern tPostMessageA HcPostMessageA;

typedef BOOL(WINAPI* tPostMessageW) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
extern tPostMessageW HcPostMessageW;

typedef BOOL(WINAPI* tSendMessageA) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
extern tSendMessageA HcSendMessageA;

typedef BOOL(WINAPI* tSendMessageW) (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
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

