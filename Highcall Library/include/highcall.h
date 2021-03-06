#ifndef HIGHCALL_H
#define HIGHCALL_H


#include "../native/native.h"

/* Include all headers for convenience. */
#include "hcdef.h"
#include "hcsyscall.h"
#include "hcimport.h"
#include "hctrampoline.h"
#include "hcmodule.h"
#include "hcstring.h"
#include "hcprocess.h"
#include "hctoken.h"
#include "hcobject.h"
#include "hcpe.h"
#include "hcvirtual.h"

typedef int HIGHCALL_STATUS;

#define HIGHCALL_ADVANCE(Status)				((HIGHCALL_STATUS)(Status) >= 0)
#define HIGHCALL_SUCCESS						((HIGHCALL_STATUS)0x00000000L)
#define HIGHCALL_FAILED							((HIGHCALL_STATUS)0xC0000001L)
#define HIGHCALL_OPENPROCESSTOKEN_UNDEFINED		((HIGHCALL_STATUS)0xC0000002L)
#define HIGHCALL_RTLGETVERSION_UNDEFINED		((HIGHCALL_STATUS)0xC0000003L)
#define HIGHCALL_WINDOWS_UNDEFINED				((HIGHCALL_STATUS)0xC0000004L)
#define HIGHCALL_SYSCALL_UNDEFINED				((HIGHCALL_STATUS)0xC0000005L)

HC_GLOBAL BOOLEAN HcGlobalElevated;
HC_GLOBAL ULONG HcGlobalWindowsVersion;

#if defined (__cplusplus)
extern "C" {
#endif

	HIGHCALL_STATUS 
		HCAPI
		HcInitialize();

#if defined (__cplusplus)
}
#endif

#endif