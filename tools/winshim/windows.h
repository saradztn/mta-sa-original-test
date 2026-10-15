/* Minimal Win32 shim - SYNTAX CHECKING ONLY. NOT the real Windows SDK, NOT linkable.
 * Lets the Windows-guarded code of this repository be *parsed* on Linux
 * (g++ -fsyntax-only -D_WIN32 ...). It declares what the sources use and
 * nothing else: no implementation, no behaviour. Never link against it.
 */
#ifndef NRTH_WINSHIM_WINDOWS_H
#define NRTH_WINSHIM_WINDOWS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef wchar_t             WCHAR;
typedef wchar_t             *LPWSTR_S;
typedef unsigned char       UCHAR;
typedef char                INT8;
typedef short               INT16;
typedef int                 INT32;
typedef unsigned long       DWORD;
typedef unsigned int        UINT;
typedef long                LONG;
typedef unsigned long       ULONG;
typedef long                HRESULT;
typedef unsigned long long  DWORD_PTR;
typedef long long           LONGLONG;
typedef unsigned long long  ULONGLONG;
typedef void               *LPVOID;
typedef const void         *LPCVOID;
typedef char               *LPSTR;
typedef wchar_t            *PWSTR;
typedef unsigned long      *PULONG;
typedef unsigned char      *PBYTE;
typedef unsigned char      *LPBYTE;
typedef unsigned long      *PDWORD;
typedef long               *PLONG;
typedef unsigned short     *PWORD;
typedef void               *PVOID;
typedef void              **PLPVOID;
typedef const char         *LPCSTR;
typedef wchar_t            *LPWSTR;
typedef const wchar_t      *LPCWSTR;
typedef void               *HANDLE;
typedef void               *HMODULE;
typedef void               *HINSTANCE;
typedef void               *HWND;
typedef void               *HICON;
typedef void               *HCURSOR;
typedef void               *HBRUSH;
typedef void               *HKEY;
typedef void                VOID;
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __fastcall
#define __fastcall
#endif
#ifndef __thiscall
#define __thiscall
#endif
#ifndef NTAPI
#define NTAPI WINAPI
#endif
#ifndef WINUSERAPI
#define WINUSERAPI
#endif
#define S_OK    ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_FAIL  ((HRESULT)0x80004005L)
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr)    (((HRESULT)(hr)) < 0)
#define ERROR_SUCCESS 0L
#define ERROR_ACCESS_DENIED 5L
#define ERROR_ALREADY_EXISTS 183L
#define ERROR_MORE_DATA 234L
#define ERROR_NO_MORE_ITEMS 259L
#define ERROR_INSUFFICIENT_BUFFER 122L
#define GENERIC_READ  0x80000000L
#define GENERIC_WRITE 0x40000000L
#define FILE_SHARE_READ  0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define OPEN_EXISTING 3
#define CREATE_ALWAYS 2
#define FILE_ATTRIBUTE_READONLY 0x00000001
#define FILE_MAP_READ 0x0004
#define FILE_MAP_ALL_ACCESS 0x000F001FL
#define HKEY_CURRENT_USER  ((HKEY)0x80000001)
#define HKEY_LOCAL_MACHINE ((HKEY)0x80000002)
#define HKEY_CLASSES_ROOT  ((HKEY)0x80000000)
#define KEY_READ  0x20019
#define KEY_WRITE 0x20006
#define KEY_ALL_ACCESS 0xF003F
#define REG_SZ 1
#define REG_DWORD 4
#define INVALID_SET_FILE_POINTER ((DWORD)0xFFFFFFFF)
#define PROCESS_TERMINATE         0x0001
#define PROCESS_CREATE_THREAD     0x0002
#define PROCESS_VM_OPERATION      0x0008
#define PROCESS_VM_READ           0x0010
#define PROCESS_VM_WRITE          0x0020
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_ALL_ACCESS        0x001F0FFF
#define THREAD_SUSPEND_RESUME     0x0002
#define CREATE_SUSPENDED          0x00000004
#define INFINITE                  0xFFFFFFFF
#define WAIT_OBJECT_0   0x00000000
#define WAIT_TIMEOUT    0x00000102
#define WAIT_FAILED     0xFFFFFFFF
#define STILL_ACTIVE    259
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3
#define DLL_PROCESS_DETACH 0
#define GET_MODULE_HANDLE_EX_FLAG_PIN               0x00000001
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000002
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS      0x00000004
#define WM_NULL         0x0000
#define WM_KEYDOWN      0x0100
#define WM_GETMINMAXINFO 0x0024
#define WM_SETCURSOR    0x0020
#define WM_INPUT        0x00FF
#define WM_MOUSEFIRST   0x0200
#define WM_MOUSELAST    0x020E
#define WH_GETMESSAGE   3
#define WH_CALLWNDPROC  4
#define IDC_ARROW       MAKEINTRESOURCEA(32512)
#define SW_HIDE         0
#define SW_SHOW         5
#define SM_CXSCREEN     0
#define SM_CYSCREEN     1
#define DONT_RESOLVE_DLL_REFERENCES 0x00000001
#define LOAD_WITH_ALTERED_SEARCH_PATH 0x00000008
#define MAKEINTRESOURCEA(i) ((char *)((unsigned long long)((unsigned short)(i))))
#define MAKEINTRESOURCEW(i) ((wchar_t *)((unsigned long long)((unsigned short)(i))))
#define GWL_WNDPROC               (-4)
#define GWLP_WNDPROC              (-4)


typedef union _LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; } u;
    long long QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEM_INFO {
    union { DWORD dwOemId; struct { WORD wProcessorArchitecture, wReserved; } s; } u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress, lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask, dwNumberOfProcessors, dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel, wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;
typedef long                NTSTATUS;
typedef void               *HGDIOBJ;
typedef void               *HHOOK;
typedef void               *FARPROC;
typedef int                (*PROC)(void);
typedef DWORD (__attribute__((stdcall)) *LPTHREAD_START_ROUTINE)(LPVOID);
typedef unsigned long       WPARAM;
typedef long                LPARAM;
typedef long                LRESULT;
typedef long long           LONG_PTR;
typedef unsigned long long  ULONG_PTR;
typedef ULONG_PTR           SIZE_T;
typedef ULONG_PTR          *PSIZE_T;
typedef LRESULT (__attribute__((stdcall)) *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL (__attribute__((stdcall)) *WNDENUMPROC)(HWND, LPARAM);
typedef LRESULT (__attribute__((stdcall)) *HOOKPROC)(int, WPARAM, LPARAM);

#ifndef WINAPI
#define WINAPI __attribute__((stdcall))
#endif
#ifndef CALLBACK
#define CALLBACK __attribute__((stdcall))
#endif
#ifndef APIENTRY
#define APIENTRY WINAPI
#endif
#ifndef WINBASEAPI
#define WINBASEAPI
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL 0
#endif
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

typedef struct _RECT { LONG left, top, right, bottom; } RECT;
typedef struct _POINT { LONG x, y; } POINT;
typedef struct _FILETIME { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;
typedef struct _RGNDATAHEADER {
    DWORD dwSize, iType, nCount, nRgnSize;
    RECT  rcBound;
} RGNDATAHEADER, *PRGNDATAHEADER;

typedef struct _RGNDATA {
    RGNDATAHEADER rdh;
    char Buffer[1];
} RGNDATA, *PRGNDATA;

typedef struct _MEMORY_BASIC_INFORMATION {
    LPVOID  BaseAddress;
    LPVOID  AllocationBase;
    DWORD   AllocationProtect;
    SIZE_T  RegionSize;
    DWORD   State;
    DWORD   Protect;
    DWORD   Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

#define MEM_COMMIT  0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_NOACCESS 0x01
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_READ 0x20

#define VK_INSERT 0x2D
#define PAGE_READONLY          0x02
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD             0x100
#define TOKEN_ADJUST_PRIVILEGES 0x0020
#define TOKEN_QUERY             0x0008
#define SE_PRIVILEGE_ENABLED    0x00000002L
#define IMAGE_DOS_SIGNATURE     0x5A4D
#define IMAGE_NT_SIGNATURE      0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

typedef struct _LUID { DWORD LowPart; LONG HighPart; } LUID, *PLUID;
typedef struct _LUID_AND_ATTRIBUTES { LUID Luid; DWORD Attributes; } LUID_AND_ATTRIBUTES;
typedef struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    WORD e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD e_res[4], e_oemid, e_oeminfo, e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine, NumberOfSections;
    DWORD TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    WORD  SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD  Magic, MajorLinkerVersion, MinorLinkerVersion;
    DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    DWORD AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
    DWORD SectionAlignment, FileAlignment;
    WORD  MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    WORD  MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
    DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    WORD  Subsystem, DllCharacteristics;
    DWORD SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    DWORD LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic, MajorLinkerVersion, MinorLinkerVersion;
    DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment, FileAlignment;
    WORD  MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    WORD  MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
    DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    WORD  Subsystem, DllCharacteristics;
    ULONGLONG SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    DWORD LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
    char Name[8];
    union { DWORD PhysicalAddress, VirtualSize; } Misc;
    DWORD VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations, NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics, TimeDateStamp;
    WORD  MajorVersion, MinorVersion;
    DWORD Name, Base, NumberOfFunctions, NumberOfNames;
    DWORD AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved, lpDesktop, lpTitle;
    DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
    DWORD dwFillAttribute, dwFlags;
    WORD wShowWindow, cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess, hThread;
    DWORD dwProcessId, dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
    char szCSDVersion[128];
} OSVERSIONINFOA;

typedef struct _MODULEINFO {
    LPVOID lpBaseOfDll;
    DWORD  SizeOfImage;
    LPVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

/* functions used by the sources */
WINBASEAPI BOOL  WINAPI CloseHandle(HANDLE);
WINBASEAPI BOOL  WINAPI CreateDirectoryA(LPCSTR, LPVOID);
WINBASEAPI HANDLE WINAPI CreateFileA(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL  WINAPI DeleteFileA(LPCSTR);
WINBASEAPI BOOL  WINAPI WriteFile(HANDLE, LPCVOID, DWORD, DWORD *, LPVOID);
WINBASEAPI BOOL  WINAPI ReadFile(HANDLE, LPVOID, DWORD, DWORD *, LPVOID);
WINBASEAPI BOOL  WINAPI GetFileSizeEx(HANDLE, void *);
WINBASEAPI DWORD WINAPI GetModuleFileNameA(HMODULE, LPSTR, DWORD);
WINBASEAPI HMODULE WINAPI GetModuleHandleA(LPCSTR);
WINBASEAPI HMODULE WINAPI LoadLibraryA(LPCSTR);
WINBASEAPI HMODULE WINAPI LoadLibraryExA(LPCSTR, HANDLE, DWORD);
WINBASEAPI int     WINAPI GetSystemMetrics(int);
WINBASEAPI BOOL    WINAPI DisableThreadLibraryCalls(HMODULE);
WINBASEAPI UINT    WINAPI GetSystemDirectoryA(LPSTR, UINT);
WINBASEAPI BOOL    WINAPI ClipCursor(const RECT *);
WINBASEAPI int     WINAPI ShowCursor(BOOL);
WINBASEAPI BOOL    WINAPI ReleaseCapture(void);
WINBASEAPI BOOL    WINAPI SetCursorPos(int, int);
WINBASEAPI HCURSOR WINAPI SetCursor(HCURSOR);
WINBASEAPI HCURSOR WINAPI LoadCursorA(HINSTANCE, void *);
WINBASEAPI HCURSOR WINAPI LoadCursorW(HINSTANCE, void *);
WINBASEAPI LRESULT WINAPI CallWindowProcW(WNDPROC, HWND, UINT, WPARAM, LPARAM);
WINBASEAPI BOOL    WINAPI SetCapture(HWND);
WINBASEAPI LRESULT WINAPI DefWindowProcW(HWND, UINT, WPARAM, LPARAM);
WINBASEAPI LONG_PTR WINAPI SetWindowLongW(HWND, int, LONG_PTR);
WINBASEAPI LONG_PTR WINAPI SetWindowLongPtrW(HWND, int, LONG_PTR);
WINBASEAPI BOOL    WINAPI GetClipCursor(RECT *);
WINBASEAPI HWND    WINAPI WindowFromPoint(POINT);
WINBASEAPI BOOL    WINAPI PostThreadMessageA(DWORD, UINT, WPARAM, LPARAM);
WINBASEAPI BOOL    WINAPI PostMessageA(HWND, UINT, WPARAM, LPARAM);
WINBASEAPI BOOL    WINAPI PostMessageW(HWND, UINT, WPARAM, LPARAM);
WINBASEAPI BOOL    WINAPI SendNotifyMessageA(HWND, UINT, WPARAM, LPARAM);
WINBASEAPI HWND    WINAPI FindWindowA(LPCSTR, LPCSTR);
WINBASEAPI int strcpy_s(char *, size_t, const char *);
WINBASEAPI int strcat_s(char *, size_t, const char *);
WINBASEAPI int sprintf_s(char *, size_t, const char *, ...);
WINBASEAPI int memcpy_s(void *, size_t, const void *, size_t);
WINBASEAPI FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR);
WINBASEAPI BOOL  WINAPI FreeLibrary(HMODULE);
WINBASEAPI short WINAPI GetAsyncKeyState(int);
WINBASEAPI BOOL  WINAPI GetCursorPos(POINT *);
WINBASEAPI BOOL  WINAPI ScreenToClient(HWND, POINT *);
WINBASEAPI BOOL  WINAPI GetClientRect(HWND, RECT *);
WINBASEAPI BOOL  WINAPI GetWindowRect(HWND, RECT *);
WINBASEAPI BOOL  WINAPI IsIconic(HWND);
WINBASEAPI HWND  WINAPI GetForegroundWindow(void);
WINBASEAPI DWORD WINAPI GetCurrentProcessId(void);
WINBASEAPI DWORD WINAPI GetCurrentThreadId(void);
WINBASEAPI void  WINAPI Sleep(DWORD);
WINBASEAPI DWORD WINAPI GetTickCount(void);
WINBASEAPI HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD *);
WINBASEAPI void  WINAPI SetLastError(DWORD);
WINBASEAPI DWORD WINAPI GetLastError(void);
WINBASEAPI BOOL  WINAPI VirtualProtect(LPVOID, SIZE_T, DWORD, DWORD *);
WINBASEAPI SIZE_T WINAPI VirtualQuery(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
WINBASEAPI LPVOID WINAPI VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL  WINAPI VirtualFree(LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL  WINAPI VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL  WINAPI VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD *);
WINBASEAPI SIZE_T WINAPI VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
WINBASEAPI int   WINAPI MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);
WINBASEAPI BOOL  WINAPI SetWindowTextW(HWND, LPCWSTR);
WINBASEAPI void *WINAPI SetWindowLongPtrA(HWND, int, LONG_PTR);
WINBASEAPI LONG_PTR WINAPI GetWindowLongPtrA(HWND, int);
WINBASEAPI LRESULT WINAPI CallWindowProcA(WNDPROC, HWND, UINT, WPARAM, LPARAM);
WINBASEAPI BOOL  WINAPI SetConsoleTitleA(LPCSTR);
WINBASEAPI BOOL  WINAPI AllocConsole(void);
WINBASEAPI HWND  WINAPI GetConsoleWindow(void);
WINBASEAPI void  WINAPI OutputDebugStringA(LPCSTR);
WINBASEAPI HANDLE WINAPI OpenProcessToken(HANDLE, DWORD, HANDLE *);
WINBASEAPI HANDLE WINAPI GetCurrentProcess(void);
WINBASEAPI BOOL  WINAPI LookupPrivilegeValueA(LPCSTR, LPCSTR, void *);
WINBASEAPI BOOL  WINAPI AdjustTokenPrivileges(HANDLE, BOOL, void *, DWORD, void *, DWORD *);
WINBASEAPI HANDLE WINAPI OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI LPVOID WINAPI VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL  WINAPI WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
WINBASEAPI HANDLE WINAPI CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD *);
WINBASEAPI DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI BOOL  WINAPI GetExitCodeThread(HANDLE, DWORD *);
WINBASEAPI BOOL  WINAPI GetExitCodeProcess(HANDLE, DWORD *);
WINBASEAPI BOOL  WINAPI TerminateProcess(HANDLE, UINT);
WINBASEAPI HANDLE WINAPI CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI BOOL  WINAPI Process32First(HANDLE, LPVOID);
WINBASEAPI BOOL  WINAPI Process32Next(HANDLE, LPVOID);
WINBASEAPI BOOL  WINAPI Module32First(HANDLE, LPVOID);
WINBASEAPI BOOL  WINAPI Module32Next(HANDLE, LPVOID);
WINBASEAPI HANDLE WINAPI FindFirstFileA(LPCSTR, LPVOID);
WINBASEAPI BOOL  WINAPI FindNextFileA(HANDLE, LPVOID);
WINBASEAPI BOOL  WINAPI FindClose(HANDLE);
WINBASEAPI BOOL  WINAPI GetWindowThreadProcessId(HWND, DWORD *);
WINBASEAPI HHOOK WINAPI SetWindowsHookExA(int, HOOKPROC, HMODULE, DWORD);
WINBASEAPI BOOL  WINAPI UnhookWindowsHookEx(void *);
WINBASEAPI HMODULE WINAPI GetModuleHandleExA(DWORD, LPCSTR, HMODULE *);
WINBASEAPI BOOL  WINAPI EnumWindows(WNDENUMPROC, LPARAM);
WINBASEAPI int   WINAPI GetWindowTextA(HWND, LPSTR, int);
WINBASEAPI ULONGLONG WINAPI GetTickCount64(void);
typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
    char cFileName[260], cAlternateFileName[14];
} WIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_NORMAL    0x80
#define INVALID_FILE_ATTRIBUTES  0xFFFFFFFF
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_MBUTTON 0x04
#define VK_ESCAPE  0x1B
#define VK_LSHIFT  0xA0
#define VK_RSHIFT  0xA1
#define VK_LCONTROL 0xA2
#define VK_RCONTROL 0xA3
#define VK_END     0x23
#define VK_F1      0x70
#define VK_SPACE   0x20
WINBASEAPI BOOL  WINAPI IsWindowVisible(HWND);
WINBASEAPI BOOL  WINAPI IsWindow(HWND);
WINBASEAPI HWND  WINAPI GetDesktopWindow(void);
WINBASEAPI HWND  WINAPI GetActiveWindow(void);
WINBASEAPI BOOL  WINAPI ShowWindow(HWND, int);
WINBASEAPI BOOL  WINAPI SetWindowPos(HWND, HWND, int, int, int, int, UINT);
WINBASEAPI BOOL  WINAPI GetKeyboardState(BYTE *);
WINBASEAPI short WINAPI GetKeyState(int);
WINBASEAPI DWORD WINAPI WaitForSingleObjectEx(HANDLE, DWORD, BOOL);
WINBASEAPI LRESULT WINAPI CallNextHookEx(void *, int, WPARAM, LPARAM);
WINBASEAPI HANDLE WINAPI GetCurrentThread(void);
WINBASEAPI DWORD WINAPI SuspendThread(HANDLE);
WINBASEAPI DWORD WINAPI ResumeThread(HANDLE);
WINBASEAPI BOOL  WINAPI FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
WINBASEAPI BOOL  WINAPI ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
WINBASEAPI void  WINAPI GetSystemInfo(LPVOID);
WINBASEAPI HANDLE WINAPI GetProcessHeap(void);
WINBASEAPI DWORD WINAPI GetFileAttributesA(LPCSTR);
WINBASEAPI HANDLE WINAPI CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
WINBASEAPI LPVOID WINAPI MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
WINBASEAPI BOOL  WINAPI UnmapViewOfFile(LPCVOID);
WINBASEAPI LONG  WINAPI InterlockedCompareExchange(volatile LONG *, LONG, LONG);
WINBASEAPI LONG  WINAPI InterlockedIncrement(volatile LONG *);
WINBASEAPI LONG  WINAPI InterlockedDecrement(volatile LONG *);
WINBASEAPI LONG  WINAPI InterlockedExchange(volatile LONG *, LONG);
WINBASEAPI LONG  WINAPI RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, HKEY *);
WINBASEAPI LONG  WINAPI RegQueryValueExA(HKEY, LPCSTR, DWORD *, DWORD *, BYTE *, DWORD *);
WINBASEAPI LONG  WINAPI RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
WINBASEAPI LONG  WINAPI RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, HKEY *, DWORD *);
WINBASEAPI LONG  WINAPI RegCloseKey(HKEY);
WINBASEAPI int   _stricmp(const char *, const char *);
WINBASEAPI int   _strnicmp(const char *, const char *, size_t);
WINBASEAPI int   _stricmp_(const char *, const char *);
WINBASEAPI LPVOID WINAPI HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL  WINAPI HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI DWORD WINAPI GetWindowThreadProcessId_(HWND, DWORD *);

#ifdef __cplusplus
}
#endif

#endif /* NRTH_WINSHIM_WINDOWS_H */
