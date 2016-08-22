#include "../include/hctoken.h"
#include "../include/hcstring.h"
#include "../include/hcsyscall.h"
#include "../include/hcvirtual.h"

typedef struct
{
	LUID Luid;
	LPCWSTR Name;
} PRIVILEGE_DATA;

/* If the first isn't defined, assume none is */
#ifndef SE_MIN_WELL_KNOWN_PRIVILEGE
#define SE_MIN_WELL_KNOWN_PRIVILEGE       2L
#define SE_CREATE_TOKEN_PRIVILEGE         2L
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE   3L
#define SE_LOCK_MEMORY_PRIVILEGE          4L
#define SE_INCREASE_QUOTA_PRIVILEGE       5L
#define SE_MACHINE_ACCOUNT_PRIVILEGE      6L
#define SE_TCB_PRIVILEGE                  7L
#define SE_SECURITY_PRIVILEGE             8L
#define SE_TAKE_OWNERSHIP_PRIVILEGE       9L
#define SE_LOAD_DRIVER_PRIVILEGE         10L
#define SE_SYSTEM_PROFILE_PRIVILEGE      11L
#define SE_SYSTEMTIME_PRIVILEGE          12L
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13L
#define SE_INC_BASE_PRIORITY_PRIVILEGE   14L
#define SE_CREATE_PAGEFILE_PRIVILEGE     15L
#define SE_CREATE_PERMANENT_PRIVILEGE    16L
#define SE_BACKUP_PRIVILEGE              17L
#define SE_RESTORE_PRIVILEGE             18L
#define SE_SHUTDOWN_PRIVILEGE            19L
#define SE_DEBUG_PRIVILEGE               20L
#define SE_AUDIT_PRIVILEGE               21L
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE  22L
#define SE_CHANGE_NOTIFY_PRIVILEGE       23L
#define SE_REMOTE_SHUTDOWN_PRIVILEGE     24L
#define SE_UNDOCK_PRIVILEGE              25L
#define SE_SYNC_AGENT_PRIVILEGE          26L
#define SE_ENABLE_DELEGATION_PRIVILEGE   27L
#define SE_MANAGE_VOLUME_PRIVILEGE       28L
#define SE_IMPERSONATE_PRIVILEGE         29L
#define SE_CREATE_GLOBAL_PRIVILEGE       30L
#define SE_MAX_WELL_KNOWN_PRIVILEGE      SE_CREATE_GLOBAL_PRIVILEGE
#endif /* ndef SE_MIN_WELL_KNOWN_PRIVILEGE */

static const PRIVILEGE_DATA WellKnownPrivileges[] =
{
	{ { SE_CREATE_TOKEN_PRIVILEGE, 0 }, SE_CREATE_TOKEN_NAME },
	{ { SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, 0 }, SE_ASSIGNPRIMARYTOKEN_NAME },
	{ { SE_LOCK_MEMORY_PRIVILEGE, 0 }, SE_LOCK_MEMORY_NAME },
	{ { SE_INCREASE_QUOTA_PRIVILEGE, 0 }, SE_INCREASE_QUOTA_NAME },
	{ { SE_MACHINE_ACCOUNT_PRIVILEGE, 0 }, SE_MACHINE_ACCOUNT_NAME },
	{ { SE_TCB_PRIVILEGE, 0 }, SE_TCB_NAME },
	{ { SE_SECURITY_PRIVILEGE, 0 }, SE_SECURITY_NAME },
	{ { SE_TAKE_OWNERSHIP_PRIVILEGE, 0 }, SE_TAKE_OWNERSHIP_NAME },
	{ { SE_LOAD_DRIVER_PRIVILEGE, 0 }, SE_LOAD_DRIVER_NAME },
	{ { SE_SYSTEM_PROFILE_PRIVILEGE, 0 }, SE_SYSTEM_PROFILE_NAME },
	{ { SE_SYSTEMTIME_PRIVILEGE, 0 }, SE_SYSTEMTIME_NAME },
	{ { SE_PROF_SINGLE_PROCESS_PRIVILEGE, 0 }, SE_PROF_SINGLE_PROCESS_NAME },
	{ { SE_INC_BASE_PRIORITY_PRIVILEGE, 0 }, SE_INC_BASE_PRIORITY_NAME },
	{ { SE_CREATE_PAGEFILE_PRIVILEGE, 0 }, SE_CREATE_PAGEFILE_NAME },
	{ { SE_CREATE_PERMANENT_PRIVILEGE, 0 }, SE_CREATE_PERMANENT_NAME },
	{ { SE_BACKUP_PRIVILEGE, 0 }, SE_BACKUP_NAME },
	{ { SE_RESTORE_PRIVILEGE, 0 }, SE_RESTORE_NAME },
	{ { SE_SHUTDOWN_PRIVILEGE, 0 }, SE_SHUTDOWN_NAME },
	{ { SE_DEBUG_PRIVILEGE, 0 }, SE_DEBUG_NAME },
	{ { SE_AUDIT_PRIVILEGE, 0 }, SE_AUDIT_NAME },
	{ { SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 0 }, SE_SYSTEM_ENVIRONMENT_NAME },
	{ { SE_CHANGE_NOTIFY_PRIVILEGE, 0 }, SE_CHANGE_NOTIFY_NAME },
	{ { SE_REMOTE_SHUTDOWN_PRIVILEGE, 0 }, SE_REMOTE_SHUTDOWN_NAME },
	{ { SE_UNDOCK_PRIVILEGE, 0 }, SE_UNDOCK_NAME },
	{ { SE_SYNC_AGENT_PRIVILEGE, 0 }, SE_SYNC_AGENT_NAME },
	{ { SE_ENABLE_DELEGATION_PRIVILEGE, 0 }, SE_ENABLE_DELEGATION_NAME },
	{ { SE_MANAGE_VOLUME_PRIVILEGE, 0 }, SE_MANAGE_VOLUME_NAME },
	{ { SE_IMPERSONATE_PRIVILEGE, 0 }, SE_IMPERSONATE_NAME },
	{ { SE_CREATE_GLOBAL_PRIVILEGE, 0 }, SE_CREATE_GLOBAL_NAME }
};

PLUID
HCAPI
HcLookupPrivilegeValueW(
	IN LPCWSTR Name)
{
	ULONG Priv;

	if (HcStringIsBadW(Name))
		return NULL;

	for (Priv = 0; Priv < sizeof(WellKnownPrivileges) / sizeof(WellKnownPrivileges[0]); Priv++)
	{
		if (HcStringEqualW(Name, WellKnownPrivileges[Priv].Name, TRUE))
			return (PLUID)&(WellKnownPrivileges[Priv].Luid);
	}

	return NULL;
}

PLUID
HCAPI
HcLookupPrivilegeValueA(
	IN LPCSTR Name)
{
	ULONG Priv; 
	LPWSTR Converted;
	DWORD NameSize;

	if (HcStringIsBadA(Name))
		return NULL;

	NameSize = HcStringSecureLengthA(Name);

	if (!NameSize)
		return NULL;

	Converted = (LPWSTR)HcAlloc(NameSize + 1);

	HcStringConvertA(Name, Converted, NameSize);

	for (Priv = 0; Priv < sizeof(WellKnownPrivileges) / sizeof(WellKnownPrivileges[0]); Priv++)
	{
		if (HcStringEqualW(Converted, WellKnownPrivileges[Priv].Name, TRUE))
		{
			HcFree(Converted);
			return (PLUID)&(WellKnownPrivileges[Priv].Luid);
		}
	}

	VirtualFree(Converted, 0, MEM_RELEASE);
	return NULL;
}

NTSTATUS
HCAPI
HcTokenIsElevated(_In_ HANDLE TokenHandle,
	_Out_ PBOOLEAN Elevated
) {
	NTSTATUS Status;
	TOKEN_ELEVATION Elevation;
	ULONG returnLength;

	Status = HcQueryInformationToken(TokenHandle,
		TokenElevation,
		&Elevation,
		sizeof(TOKEN_ELEVATION),
		&returnLength);

	if (NT_SUCCESS(Status))
	{
		*Elevated = !!Elevation.TokenIsElevated;
	}

	return Status;
}
