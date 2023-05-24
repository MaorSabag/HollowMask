#include <windows.h>

// kernel32 function
typedef HMODULE(WINAPI* LOADLIBRARYA)(
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