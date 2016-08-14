#pragma once
#include "hcdef.h"
#include "native.h"


mem_result
HCAPI
HcInternalMemoryTest(SIZE_T dwBaseAddress, SIZE_T dwBufferLength);

mem_result
HCAPI
HcInternalMemoryTest(SIZE_T dwBaseAddress, SIZE_T* pdwOffsets, SIZE_T dwOffsetCount, SIZE_T dwBufferLength);

LPCSTR
HCAPI
HcInternalReadString(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount);

LPCSTR
HCAPI
HcInternalReadString(SIZE_T memAddress);

SIZE_T
HCAPI
HcInternalReadInt(SIZE_T memAddress, SIZE_T* ptrOffsets, SIZE_T offsetCount);

int
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
