#include <hcapi.h>
#include <highcall.h>
#include <hcprocess.h>
#include <hcstring.h>
#include <hcsyscall.h>
#include <hcmodule.h>

#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "highcall.lib")

/*
If true is returned, it stops the iteration
If false is returned, it goes to the next untill there is no more modules to loop
*/
BOOL ModuleCallback(HC_MODULE_INFORMATION hcInfo, LPARAM lPARAM)
{
	wprintf(L"\n\t\t%s\n", hcInfo.Name);
#ifdef _WIN64
	wprintf(L"\t\tBase Address:%llx\n", hcInfo.Base);
	wprintf(L"\t\tSize of Module:%llx\n", hcInfo.Size);
#else
	wprintf(L"\t\tBase Address:%x\n", hcInfo.Base);
	wprintf(L"\t\tSize of Module:%x\n", hcInfo.Size);
#endif
	wprintf(L"\t\tPath:%s\n", hcInfo.Path);

	/* We just want to loop all of them, so keep going regardless */
	return FALSE;
}

/*
	If true is returned, it stops the iteration
	If false is returned, it goes to the next untill there is no more processes to loop
*/
BOOL ProcessCallback(HC_PROCESS_INFORMATION hpcInfo, LPARAM lParam)
{
	wprintf(L"\nProcess %s\n", hpcInfo.Name);
	wprintf(L"\tAccessible? %s\n", hpcInfo.CanAccess ? L"true" : L"false");
	
	if (!hpcInfo.CanAccess)
	{
		wprintf(L"--------------");
		return FALSE;
	}

	/* We need a handle first */
	HANDLE ProcessHandle;
	ProcessHandle = HcProcessOpen(hpcInfo.Id, PROCESS_ALL_ACCESS);

	if (!ProcessHandle)
	{
		return FALSE;
	}

	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION BasicInformation;
	
	/* include hcsyscall.h */

	/* Ask the kernel for the basic information of this process */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessBasicInformation,
		&BasicInformation,
		sizeof(BasicInformation),
		NULL);

	if (!NT_SUCCESS(Status))
	{
		wprintf(L"\tPEB Address not found.\n");
	}
	else
	{
#ifdef _WIN64
		wprintf(L"\tPEB Address: %llx\n", (SIZE_T)BasicInformation.PebBaseAddress);
#else
		wprintf(L"\tPEB Address: %x\n", (SIZE_T)BasicInformation.PebBaseAddress);
#endif // _WIN64
	}

	/* Enumerate modules */
	wprintf(L"\tModules:\n");

	/* Enumerate modules */
	HcProcessEnumModules(ProcessHandle, ModuleCallback, NULL);

	HcCloseHandle(ProcessHandle);

	return FALSE;
}

/*
If true is returned, it stops the iteration
If false is returned, it goes to the next untill there is no more processes to loop
*/
BOOL HiddenModuleCallback(HC_PROCESS_INFORMATION hpcInfo, LPARAM lParam)
{
	wprintf(L"\nProcess %s\n", hpcInfo.Name);
	wprintf(L"\tAccessible? %s\n", hpcInfo.CanAccess ? L"Yes" : L"No");

	if (!hpcInfo.CanAccess)
	{
		wprintf(L"--------------");
		return FALSE;
	}

	/* Enumerate modules */
	wprintf(L"\tModules:\n");

	/* We need a handle first */
	HANDLE ProcessHandle;
	ProcessHandle = HcProcessOpen(hpcInfo.Id, PROCESS_ALL_ACCESS);

	if (!ProcessHandle)
	{
		return FALSE;
	}

	/* Enumerate hidden modules */
	HcProcessEnumModulesEx(ProcessHandle, ModuleCallback, NULL);

	HcCloseHandle(ProcessHandle);

	return FALSE;
}

BOOL ExportCallback(LPCSTR name, LPARAM param)
{
	if (strlen(name) < 4)
	{
		return FALSE;
	}

	if (!memcmp(name, "Zw", 2))
	{
		DWORD Index = HcSyscallIndexA(name);
		printf("%s, index: %x\n", name, Index);
	}
	return FALSE;
}

int wmain(int argc, wchar_t *argv[])
{
	HIGHCALL_STATUS Status;

	/* Start Highcall. */
	Status = HcInitialize();

	/* Check if we failed. */
	if (!HIGHCALL_ADVANCE(Status))
	{
		printf("Could not start Highcall, Status: %x\n", Status);
		return -1;
	}

	printf("Highcall initialized.\n");

	printf("Acquiring debug privilege: ");

	/* Get debug privilege for protected processes. */
	if (HcProcessSetPrivilegeW(NtCurrentProcess, SE_DEBUG_NAME, TRUE))
	{
		printf("success.\n");
	}
	else
	{
		printf("failed.\n");
	}

	printf("\n\nPress any key to enumerate modules of your processes.\n\n");
	_getch();

	/* include hcprocess.h */
	/*
		arg1 - NULL 
			Search for processes with any name
		arg2 - BOOL function
			function to call on each process callback
		arg3 - LPARAM
			any parameter to pass to the callback
	*/
	HcProcessQueryByName(NULL, ProcessCallback, NULL);

	/* We're done enumerating normal modules */
	printf("\n\nPress any key to enumerate hidden modules of your processes.\n\n");
	_getch();

	/* Enumerate hidden modules */
	HcProcessQueryByName(NULL, HiddenModuleCallback, NULL);

	printf("Press any key to enumerate all syscall indexes.\n");
	_getch();

	/* Include hcmodule.h */

	wprintf(L"Syscall Indexes\n");

	/* Get the address of NTDLL */
	HMODULE ntdll = HcModuleHandleA("ntdll.dll");

#ifdef _WIN64
	wprintf(L"NTDLL Address: %llx\n", ntdll);
#else
	wprintf(L"NTDLL Address: %x\n", ntdll);
#endif

	/* List the syscall indexes */
	HcModuleListExports(ntdll, ExportCallback, 0);

	getchar();
	return 0;
}