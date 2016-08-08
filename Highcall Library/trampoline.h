#pragma once
#include "type.h"

BOOL WINAPI HcWindowThreadProcessId(_In_ HWND hWnd, _Out_opt_ LPDWORD lpdwProcessId);

BOOL WINAPI HcGetCursorPos(_Out_ LPPOINT lpPoint);

BOOL WINAPI HcPostMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

BOOL WINAPI HcPostMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

BOOL WINAPI HcSendMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

BOOL WINAPI HcSendMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

HANDLE WINAPI HcCreateRemoteThread(
	_In_  HANDLE                 hProcess,
	_In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	_In_  SIZE_T                 dwStackSize,
	_In_  LPTHREAD_START_ROUTINE lpStartAddress,
	_In_  LPVOID                 lpParameter,
	_In_  DWORD                  dwCreationFlags,
	_Out_ LPDWORD                lpThreadId
);