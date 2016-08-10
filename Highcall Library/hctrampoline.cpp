#include "hctrampoline.h"
#include "hcapi.h"
#include "../distorm/include/distorm.h"

DWORD HCAPI HcTrampolineCalculateLength(BYTE* Src, DWORD NeededLength)
{
	DWORD InstructionSize = 0;
	BOOLEAN BigEnough = FALSE;
	unsigned int decodedInstructionsCount = 0;
	_DecodedInst decodedInstructions[0x100];

	if (!Src)
	{
		return 0;
	}

	/* Decode the instructions */
	if (distorm_decode(0,
		Src,
		0x100,
#ifdef _WIN64
		Decode64Bits,
#else
		Decode32Bits,
#endif
		decodedInstructions,
		0x100,
		&decodedInstructionsCount) == DECRES_INPUTERR)
	{
		return 0;
	}

	/* Loop over the instructions untill we find a suitable size. */
	for (unsigned int i = 0; i < decodedInstructionsCount && !BigEnough; i++)
	{
		InstructionSize += decodedInstructions[i].size;

		if (InstructionSize >= NeededLength)
			BigEnough = true;
	}

	if (!BigEnough)
		InstructionSize = 0;

	return InstructionSize;
}

PVOID HCAPI HcTrampolineOriginal(PBYTE lpBaseAddress, DWORD dwMinimumSize)
{
	PVOID Recreated = 0;
	PBYTE Original;
	DWORD SizeOfFunction;
	PBYTE Jump;
	DWORD SizeOfJump;
	PBYTE opCode;
	DWORD SizeOfOpcode;
	DWORD dwRequiredSize;

	if (!lpBaseAddress)
	{
		return 0;
	}

	dwRequiredSize = HcTrampolineCalculateLength(lpBaseAddress, dwMinimumSize);
	if (!dwRequiredSize)
	{
		return 0;
	}

	Original = (PBYTE) VirtualAlloc(NULL,
		dwRequiredSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!HcReadModuleAddressDisk(lpBaseAddress, Original, dwRequiredSize))
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

	SizeOfFunction = dwRequiredSize + SizeOfJump;

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
	memcpy(Recreated, Original, dwRequiredSize);

	VirtualFree(Original, 0, MEM_RELEASE);

	Jump = (PBYTE)VirtualAlloc(0,
		SizeOfJump,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	memcpy(Jump, opCode, SizeOfOpcode);
	VirtualFree(opCode, 0, MEM_RELEASE);

#ifndef _WIN64
	/* Relative jump back */
	*(DWORD*)(Jump + SizeOfOpcode) = (DWORD)((SIZE_T)lpBaseAddress - (SIZE_T) Recreated - SizeOfFunction + dwRequiredSize);
#else
	*(SIZE_T*)&Jump[3] = (SIZE_T)lpBaseAddress + dwRequiredSize;
#endif

	/* Copy the jump back to the continued code */
	memcpy((LPVOID)((SIZE_T)Recreated + dwRequiredSize), Jump, SizeOfJump);
	return Recreated;
}