#include "hctrampoline.h"
#include "hcapi.h"

PVOID HCAPI HcTrampolineOriginal(PBYTE lpBaseAddress, DWORD dwSizeToRestore)
{
	PVOID Recreated = 0;
	PBYTE Original;
	DWORD SizeOfFunction;
	PBYTE Jump;
	DWORD SizeOfJump;
	PBYTE opCode;
	DWORD SizeOfOpcode;

	Original = (PBYTE) VirtualAlloc(NULL,
		dwSizeToRestore,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!HcReadModuleAddressDisk(lpBaseAddress, Original, dwSizeToRestore))
	{
		VirtualFree(Original, 0, MEM_RELEASE);
		return 0;
	}

#ifdef _WIN64
	SizeOfOpcode = 16;
#else
	SizeOfOpcode = 1;
#endif

	opCode = (PBYTE)VirtualAlloc(0,
		SizeOfOpcode,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

#ifndef _WIN64
	/* jmp dword ptr */
	opCode[0] = 0xE9;
	SizeOfJump = 5;
#else
	/* Jump code, CC will be replaced later. */
	BYTE x64Jump[] = 
	{
		0x50,															/* push rax */
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,		/* movabs rax, 0xCCCCCCCCCCCCCCCC */
		0x48, 0x87, 0x04, 0x24,											/* xchg rax, [rsp] */
		0xC3															/* ret */
	};
	memcpy(opCode, x64Jump, sizeof(x64Jump));
	SizeOfJump = sizeof(x64Jump);
#endif

	SizeOfFunction = dwSizeToRestore + SizeOfJump;

	/* Allocate for the new function */
	Recreated = VirtualAlloc(0,
		SizeOfFunction,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	if (!Recreated)
	{
		VirtualFree(Original, 0, MEM_RELEASE);
		VirtualFree(opCode, 0, MEM_RELEASE);
		return 0;
	}

	/* Copy original to the new function */
	memcpy(Recreated, Original, dwSizeToRestore);

	VirtualFree(Original, 0, MEM_RELEASE);

	Jump = (PBYTE)VirtualAlloc(0,
		SizeOfJump,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	memcpy(Jump, opCode, SizeOfOpcode);
	VirtualFree(opCode, 0, MEM_RELEASE);

#ifndef _WIN64
	/* Set the destination of the jump */
	*(DWORD*)(Jump + SizeOfOpcode) = (DWORD)((SIZE_T)lpBaseAddress - (SIZE_T) Recreated - SizeOfFunction + dwSizeToRestore);
#else
	*(SIZE_T*)&Jump[3] = (SIZE_T)lpBaseAddress + dwSizeToRestore;
#endif

	/* Copy the jump back to the continued code */
	memcpy((LPVOID)((SIZE_T)Recreated + dwSizeToRestore), Jump, SizeOfJump);
	return Recreated;
}


/*
MEMORY_BASIC_INFORMATION mbi;
for (SIZE_T addr = (SIZE_T)lpBaseAddress; addr > (SIZE_T)lpBaseAddress - 0x80000000; addr = (SIZE_T)mbi.BaseAddress - 1)
{
if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
{
break;
}

if (mbi.State == MEM_FREE)
{
}
}
*/