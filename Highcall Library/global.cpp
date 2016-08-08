#include "global.h"
#include "hcapi.h"
#include "syscall.h"
#include "import.h"

ULONG WindowsVersion;
BOOLEAN HcElevated;

typedef BYTE Unused;

static Unused HcInitializeSecurity(VOID)
{
	HANDLE hToken;

	if (NT_SUCCESS(HcOpenProcessToken(NtCurrentProcess,
		TOKEN_QUERY,
		&hToken)))
	{
		HcGetTokenIsElevated(hToken, &HcElevated);
	}

	return 1;
}

static Unused HcInitializeWindowsVersion(VOID)
{
	RTL_OSVERSIONINFOEXW versionInfo;
	ULONG majorVersion;
	ULONG minorVersion;

	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&versionInfo)))
	{
		return 0;
	}

	majorVersion = versionInfo.dwMajorVersion;
	minorVersion = versionInfo.dwMinorVersion;

	/* Windows 7 */
	if (majorVersion == 6 && minorVersion == 1)
	{
		WindowsVersion = WINDOWS_7;
	}
	/* Windows 8.0 */
	else if (majorVersion == 6 && minorVersion == 2)
	{
		WindowsVersion = WINDOWS_8;
	}
	/* Windows 8.1 */
	else if (majorVersion == 6 && minorVersion == 3)
	{
		WindowsVersion = WINDOWS_8_1;
	}
	/* Windows 10 */
	else if (majorVersion == 10 && minorVersion == 0)
	{
		WindowsVersion = WINDOWS_10;
	}
	else
	{
		WindowsVersion = WINDOWS_NOT_SUPPORTED;
	}

	return 1;
}

/* C++ Dynamic initialization. 
	Sort of hackish, you just call the function to get it to set some variables.
	I swear there has to be an easier way of doing this. */

static Unused _ver_unused = HcInitializeWindowsVersion();
static Unused _sec_unused = HcInitializeSecurity();