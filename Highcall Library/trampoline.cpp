#include "trampoline.h"
#include "hcapi.h"
#include "global.h"

TrampolineJump tjGetWindowThreadProcessId = HcGetProcedureAddress(USER32, "GetWindowThreadProcessId") + 5;
__declspec(naked) BOOL WINAPI HcWindowThreadProcessId(_In_ HWND hWnd, _Out_opt_ LPDWORD lpdwProcessId)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp[tjGetWindowThreadProcessId]
	}
}

TrampolineJump tjGetCursorPos = HcGetProcedureAddress(USER32, "GetCursorPos") + 5;
__declspec(naked) BOOL WINAPI HcGetCursorPos(
	_Out_ LPPOINT lpPoint
) {
	__asm
	{
		mov edi, edi
		push ebp
		mov ebp, esp
		jmp[tjGetCursorPos]
	}
}

TrampolineJump tjPostMessageA = HcGetProcedureAddress(USER32, "PostMessageA") + 5;
__declspec(naked) BOOL WINAPI HcPostMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp[tjPostMessageA]
	}
}

TrampolineJump tjPostMessageW = HcGetProcedureAddress(USER32, "PostMessageW") + 5;
__declspec(naked) BOOL WINAPI HcPostMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp[tjPostMessageW]
	}
}

TrampolineJump tjSendMessageA = HcGetProcedureAddress(USER32, "SendMessageA") + 5;
__declspec(naked) BOOL WINAPI HcSendMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp[tjSendMessageA]
	}
}

TrampolineJump tjSendMessageW = HcGetProcedureAddress(USER32, "SendMessageW") + 5;
__declspec(naked) BOOL WINAPI HcSendMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp[tjSendMessageW]
	}
}

TrampolineJump tjCreateRemoteThread = HcGetProcedureAddress(KERNEL32, "CreateRemoteThread") + 5;
__declspec(naked) HANDLE WINAPI HcCreateRemoteThread(
	_In_  HANDLE                 hProcess,
	_In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	_In_  SIZE_T                 dwStackSize,
	_In_  LPTHREAD_START_ROUTINE lpStartAddress,
	_In_  LPVOID                 lpParameter,
	_In_  DWORD                  dwCreationFlags,
	_Out_ LPDWORD                lpThreadId
) {
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp[tjCreateRemoteThread]
	}
}
