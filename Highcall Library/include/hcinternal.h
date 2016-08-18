#ifndef HC_INTERNAL_H
#define HC_INTERNAL_H

#include "hcdef.h"
#include "../native/native.h"

#if defined (__cplusplus)
extern "C" {
#endif

	mem_result
		HCAPI
		HcInternalMemoryTest(SIZE_T dwBaseAddress, SIZE_T dwBufferLength);

	mem_result
		HCAPI
		HcInternalMemoryTestEx(SIZE_T dwBaseAddress, SIZE_T* pdwOffsets, SIZE_T dwOffsetCount, SIZE_T dwBufferLength);

	LPCSTR
		HCAPI
		HcInternalReadStringEx(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount);

	LPCSTR
		HCAPI
		HcInternalReadString(SIZE_T memAddress);

	SIZE_T
		HCAPI
		HcInternalReadIntEx(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount);

	SIZE_T
		HCAPI
		HcInternalReadInt(SIZE_T baseAddress);

	SIZE_T
		HCAPI
		HcInternalLocatePointer(SIZE_T baseAddress, SIZE_T* offsets, unsigned int offsetCount);

	VOID
		HCAPI
		HcInternalMemoryWrite(PVOID pAddress, SIZE_T dwLen, BYTE* ptrWrite);

	VOID
		HCAPI
		HcInternalMemoryNop(PVOID pAddress, SIZE_T dwLen);

	SIZE_T
		HCAPI
		HcInternalPatternFind(const char* pattern, const char* mask, HC_MODULE_INFORMATION module);

	BOOLEAN
		HCAPI
		HcInternalMainModule(PHC_MODULE_INFORMATION hcmInfo);

#endif

#if defined (__cplusplus)
}
#endif