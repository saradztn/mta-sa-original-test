/* Win32 toolhelp shim - syntax checking only (see windows.h in this dir). */
#ifndef NRTH_WINSHIM_TLHELP32_H
#define NRTH_WINSHIM_TLHELP32_H
#include "windows.h"
#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPPROCESS  0x00000002
#define TH32CS_SNAPTHREAD   0x00000004
#define TH32CS_SNAPMODULE   0x00000008
#define TH32CS_SNAPMODULE32 0x00000010
#define TH32CS_SNAPALL      0x0000000F
typedef struct _PROCESSENTRY32 {
    DWORD dwSize, cntUsage, th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID, cntThreads, th32ParentProcessID;
    LONG  pcPriClassBase;
    DWORD dwFlags;
    char  szExeFile[260];
} PROCESSENTRY32, *LPPROCESSENTRY32;
typedef struct _THREADENTRY32 {
    DWORD dwSize, cntUsage, th32ThreadID, th32OwnerProcessID;
    LONG  tpBasePri, tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32, *LPTHREADENTRY32;
typedef struct _MODULEENTRY32 {
    DWORD dwSize, th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
    BYTE *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    char szModule[256];
    char szExePath[260];
} MODULEENTRY32, *LPMODULEENTRY32;
#ifdef __cplusplus
extern "C" {
#endif
WINBASEAPI BOOL WINAPI Thread32First(HANDLE, LPTHREADENTRY32);
WINBASEAPI BOOL WINAPI Thread32Next(HANDLE, LPTHREADENTRY32);
#ifdef __cplusplus
}
#endif
#endif
