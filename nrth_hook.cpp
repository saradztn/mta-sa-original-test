/* ============================================================================
 *  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
 *  Security & Vulnerability Research Team — White Hat Hackers
 * ----------------------------------------------------------------------------
 *  MTA:SA security research test bed — mta-sa-original-test
 *  Internal security research material. All rights reserved by the team above.
 *  Redistribution, public release and reuse outside the team are not authorized.
 *  NRTH-SEC-RESEARCH-HEADER
 * ============================================================================ */





























#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <psapi.h>
#ifndef NRTH_HEADLESS_TEST
#include <d3d9.h>
#include "MinHook.h"
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include "nrth_fonts.h"
#endif
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_hook.h"
#include "nrth_ui.h"






#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
__asm__(
    ".section .text\n"
    ".balign 16, 0x90\n"
    ".fill 0xA9E0, 1, 0x90\n"
);
#endif

extern "C"
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
__attribute__((aligned(16)))
#endif
LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
#ifdef _WIN32
    return CallNextHookEx(NULL, nCode, wParam, lParam);
#else
    (void)nCode;
    (void)wParam;
    return (LRESULT)lParam;
#endif
}




static int nrth_hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint32_t nrth_compile_pat(const char *pat, uint8_t *bytes, uint8_t *mask, uint32_t cap)
{
    if (!pat || !bytes || !mask) return 0;
    uint32_t n = 0;
    const char *p = pat;
    while (*p && n < cap) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (*p == '?') {
            bytes[n] = 0;
            mask[n]  = 0;
            ++n;
            while (*p && *p != ' ' && *p != '\t') ++p;
            continue;
        }
        int hi = nrth_hex_digit((unsigned char)p[0]);
        int lo = (p[1] && nrth_hex_digit((unsigned char)p[1]) >= 0)
                     ? nrth_hex_digit((unsigned char)p[1]) : -1;
        if (hi < 0) return 0;
        bytes[n] = (uint8_t)((lo >= 0) ? (hi * 16 + lo) : hi);
        mask[n]  = 0xFF;
        ++n;
        while (*p && *p != ' ' && *p != '\t') ++p;
    }
    return n;
}

static uint32_t g_TotalPatternScans    = 0;
static uint32_t g_TotalInstalledHooks  = 0;
static uint32_t g_TotalAppliedPatches  = 0;

extern "C" const uint8_t *ResolvePattern_10002960(const uint8_t *base, uint32_t size,
                                                  const char *pattern)
{
    ++g_TotalPatternScans;
    if (!base || size == 0 || !pattern || !pattern[0]) {
        return NULL;
    }
    uint8_t bytes[256];
    uint8_t mask[256];
    uint32_t plen = nrth_compile_pat(pattern, bytes, mask, 256);
    if (plen == 0 || plen > size) {
        return NULL;
    }
    uint32_t anchor = 0;
    while (anchor < plen && mask[anchor] == 0) {
        ++anchor;
    }
    if (anchor >= plen) {
        return NULL;
    }
    uint8_t ab = bytes[anchor];
    for (uint32_t i = anchor; i + (plen - anchor) <= size; ++i) {
        if (base[i] != ab) continue;
        uint32_t start = i - anchor;
        bool ok = true;
        for (uint32_t j = 0; j < plen; ++j) {
            if (mask[j] && base[start + j] != bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return base + start;
        }
    }
    return NULL;
}




static char s_sigPlainBuf[20][160] = {{0}};
static bool s_sigGate[20]          = {false};

static const char *DecryptCatalogSig(uint32_t sigId1Based)
{
    if (sigId1Based < 1 || sigId1Based > 20) {
        return "";
    }
    uint32_t idx = sigId1Based - 1;
    const NrthEncryptedSigEntry &e = kNrthEncryptedSigs[idx];
    return NrthDecryptOnce(e.cipher, e.fieldSize, e.key, s_sigPlainBuf[idx], &s_sigGate[idx]);
}




static NrthLuaVmBridge        g_LuaVmBridge       = {};
static SPlayerHealthSync      g_PlayerHealthSync  = {
    100.0f, 100.0f, 0, 0, 0, 0, 1.0f, 0.5f, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static SWeaponAimSync         g_WeaponAimSync     = { 0.0f, 0.0f, 0.0f, 300.0f, 12.0f, 0, 1, 1, 0 };
static NrthReportChannelState g_ReportChannels    = { 0, 0, 0, 0, 0, false };

extern "C" NrthLuaVmBridge *Nrth_GetLuaVmBridge(void)
{
    return &g_LuaVmBridge;
}

extern "C" SPlayerHealthSync *Nrth_GetPlayerHealthSync(void)
{
    return &g_PlayerHealthSync;
}

extern "C" SWeaponAimSync *Nrth_GetWeaponAimSync(void)
{
    return &g_WeaponAimSync;
}

extern "C" NrthReportChannelState *Nrth_GetReportChannelState(void)
{
    return &g_ReportChannels;
}

extern "C" bool Nrth_IsPointerReadable_VirtualQuery(const void *ptr)
{
    if (!ptr) {
        return false;
    }
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    DWORD readableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & readableMask) == 0 || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    return true;
#else
    return ((uintptr_t)ptr >= 0x1000u);
#endif
}




static NrthPatchRecord g_PatchList_101493e4[NRTH_NETC_PATCH_COUNT] = {
    { 0x100206e5u, 0x100206f0u, 0x10023670u, NULL, 0, 0xC3u, 0, 0 },
    { 0x1002089fu, 0x100208aau, 0x10023530u, NULL, 0, 0xC3u, 0, 0 },
    { 0x1002091cu, 0x10020927u, 0x100233f0u, NULL, 0, 0xC3u, 0, 0 },
    { 0x10020f3bu, 0x10020f46u, 0x100232b0u, NULL, 0, 0xC3u, 0, 0 },
    { 0x100214b2u, 0x100214bdu, 0x10023170u, NULL, 0, 0xC3u, 0, 0 },
    { 0x100215e6u, 0x100215f1u, 0x10023030u, NULL, 0, 0xC3u, 0, 0 },
};

extern "C" bool PatchByte_10011870(void *targetAddr, uint8_t opcodeByte, uint32_t prepVa,
                                   uint32_t callVa, uint32_t patternGlobal)
{
    if (callVa < prepVa || (callVa - prepVa) != 11u) {
        return false;
    }

    NrthPatchRecord *rec = NULL;
    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        if (g_PatchList_101493e4[i].prepVa == prepVa &&
            g_PatchList_101493e4[i].callVa == callVa) {
            rec = &g_PatchList_101493e4[i];
            break;
        }
    }

    if (rec) {
        rec->patternGlobal = patternGlobal;
        rec->targetAddr    = targetAddr;
        rec->patchByte     = opcodeByte;
    }

    if (!targetAddr) {
        return false;
    }

    uint8_t *pByte = (uint8_t *)targetAddr;
#ifdef _WIN32
    DWORD oldProt = 0;
    if (!VirtualProtect(targetAddr, 1, PAGE_EXECUTE_READWRITE , &oldProt)) {
        return false;
    }
    uint8_t prev = *pByte;
    *pByte = opcodeByte;
    DWORD dummy = 0;
    VirtualProtect(targetAddr, 1, oldProt, &dummy);
#else
    uint8_t prev = *pByte;
    *pByte = opcodeByte;
#endif

    if (rec) {
        rec->origByte = prev;
        rec->applied  = 1;
    }
    ++g_TotalAppliedPatches;
    return true;
}
















static void *g_pClientGame_10148ee8     = NULL;
static void *g_ClientIfaces_10148ed4[6] = { NULL };
static void *g_ResourceMgr_1013c948     = NULL;


#ifndef NRTH_CDECL
#ifdef _WIN32
#define NRTH_CDECL __cdecl
#else
#define NRTH_CDECL
#endif
#endif
typedef int         (NRTH_CDECL *PFN_lua_CFunction)(void *L);
typedef int         (NRTH_CDECL *PFN_lua_pcall_t)(void *L, int nargs, int nresults, int errfunc);
typedef size_t      (NRTH_CDECL *PFN_lua_objlen_t)(void *L, int idx);
typedef void        (NRTH_CDECL *PFN_lua_rawseti_t)(void *L, int idx, int n);
typedef const char *(NRTH_CDECL *PFN_lua_tolstring_t)(void *L, int idx, size_t *len);
typedef void        (NRTH_CDECL *PFN_lua_pushcclosure_t)(void *L, PFN_lua_CFunction fn, int n);
typedef int         (NRTH_CDECL *PFN_lua_type_t)(void *L, int idx);
typedef double      (NRTH_CDECL *PFN_lua_tonumber_t)(void *L, int idx);
typedef int         (NRTH_CDECL *PFN_lua_gettop_t)(void *L);
typedef void        (NRTH_CDECL *PFN_lua_pushnumber_t)(void *L, double n);
typedef void        (NRTH_CDECL *PFN_lua_pushstring_t)(void *L, const char *s);
typedef void        (NRTH_CDECL *PFN_lua_settop_t)(void *L, int idx);
typedef void        (NRTH_CDECL *PFN_lua_createtable_t)(void *L, int narr, int nrec);
typedef void        (NRTH_CDECL *PFN_lua_setfield_t)(void *L, int idx, const char *k);
typedef void        (NRTH_CDECL *PFN_lua_rawgeti_t)(void *L, int idx, int n);

static PFN_lua_pcall_t        g_lua_pcall_1013c974        = NULL;
static PFN_lua_objlen_t       g_lua_objlen_1013c978       = NULL;
static PFN_lua_rawseti_t      g_lua_rawseti_1013c97c      = NULL;
static PFN_lua_tolstring_t    g_lua_tolstring_1013c980    = NULL;
static PFN_lua_pushcclosure_t g_lua_pushcclosure_1013c984 = NULL;
static PFN_lua_type_t         g_lua_type_1013c988         = NULL;
static PFN_lua_tonumber_t     g_lua_tonumber_1013c98c     = NULL;
static PFN_lua_gettop_t       g_lua_gettop_1013c990       = NULL;
static PFN_lua_pushnumber_t   g_lua_pushnumber_1013c994   = NULL;
static PFN_lua_pushstring_t   g_lua_pushstring_1013c998   = NULL;
static PFN_lua_settop_t       g_lua_settop_1013c99c       = NULL;
static PFN_lua_createtable_t  g_lua_createtable_1013c9a0  = NULL;
static PFN_lua_setfield_t     g_lua_setfield_1013c9a4     = NULL;
static PFN_lua_rawgeti_t      g_lua_rawgeti_1013c9a8      = NULL;

struct NrthActiveResourceSlot {
    char  name[64];
    void *resPtr;
};
static NrthActiveResourceSlot s_activeResources[128] = {};
static uint32_t               s_activeResourceCount  = 0;
static char                   s_stoppedResources[128][64] = {{0}};
static uint32_t               s_stoppedResourceCount = 0;


static int NRTH_CDECL LuaApi_StoppedResources_1000f920(void *L)
{
    if (!L || !g_lua_gettop_1013c990 || !g_lua_type_1013c988 ||
        !g_lua_tolstring_1013c980 || !g_lua_objlen_1013c978 || !g_lua_rawgeti_1013c9a8) {
        return 0;
    }
    int nargs = g_lua_gettop_1013c990(L);
    if (nargs < 1) {
        return 0;
    }
    int argIdx = 1;
    int t1 = g_lua_type_1013c988(L, 1);
    if (t1 == 4) {
        size_t slen = 0;
        const char *s = g_lua_tolstring_1013c980(L, 1, &slen);
        if (s && slen > 0) {
            Nrth_StopClientResource_100054a0(s);
        }
        return 0;
    }
    if (t1 == 5 && nargs >= 2) {
        int t2 = g_lua_type_1013c988(L, 2);
        if (t2 == 4) {
            size_t slen = 0;
            const char *s = g_lua_tolstring_1013c980(L, 2, &slen);
            if (s && slen > 0) {
                Nrth_StopClientResource_100054a0(s);
            }
            return 0;
        }
        argIdx = 2;
    }
    if (g_lua_type_1013c988(L, argIdx) == 5 && g_lua_settop_1013c99c) {
        size_t count = g_lua_objlen_1013c978(L, argIdx);
        for (size_t i = 1; i <= count; ++i) {
            g_lua_rawgeti_1013c9a8(L, argIdx, (int)i);
            if (g_lua_type_1013c988(L, -1) == 4) {
                size_t slen = 0;
                const char *s = g_lua_tolstring_1013c980(L, -1, &slen);
                if (s && slen > 0) {
                    Nrth_StopClientResource_100054a0(s);
                }
            }
            g_lua_settop_1013c99c(L, -2);
        }
    }
    return 0;
}

static int NRTH_CDECL LuaApi_ShootBullet_1000fe90(void *L)
{
    (void)L;
    return 0;
}

static int NRTH_CDECL LuaApi_GetMarkersPos_10010cc0(void *L)
{
    if (!L || !g_lua_gettop_1013c990 || !g_lua_tolstring_1013c980 ||
        !g_lua_pushstring_1013c998 || !g_lua_setfield_1013c9a4 ||
        !g_lua_type_1013c988 || !g_lua_rawseti_1013c97c ||
        !g_lua_createtable_1013c9a0 || !g_lua_objlen_1013c978 ||
        !g_lua_pushnumber_1013c994) {
        return 0;
    }
    if (g_lua_gettop_1013c990(L) < 1 || g_lua_type_1013c988(L, 1) != 4) {
        return 0;
    }
    size_t qlen = 0;
    const char *query = g_lua_tolstring_1013c980(L, 1, &qlen);
    if (!query) {
        return 0;
    }
    uint32_t mCount = NrthUI_GetMarkerCount();
    if (strcmp(query, "all") == 0) {
        g_lua_createtable_1013c9a0(L, 0, 0);
        for (uint32_t i = 0; i < mCount; ++i) {
            float mx = 0.0f, my = 0.0f, mz = 0.0f;
            if (NrthUI_GetMarkerAt(i, &mx, &my, &mz)) {
                char mName[32];
                snprintf(mName, sizeof(mName), "Marker #%u", (unsigned)(i + 1));
                g_lua_createtable_1013c9a0(L, 0, 0);
                g_lua_pushstring_1013c998(L, mName);
                g_lua_setfield_1013c9a4(L, -2, "name");
                g_lua_pushnumber_1013c994(L, (double)mx);
                g_lua_setfield_1013c9a4(L, -2, "x");
                g_lua_pushnumber_1013c994(L, (double)my);
                g_lua_setfield_1013c9a4(L, -2, "y");
                g_lua_pushnumber_1013c994(L, (double)mz);
                g_lua_setfield_1013c9a4(L, -2, "z");
                g_lua_rawseti_1013c97c(L, -2, (int)(i + 1));
            }
        }
        return 1;
    }
    for (uint32_t i = 0; i < mCount; ++i) {
        float mx = 0.0f, my = 0.0f, mz = 0.0f;
        if (NrthUI_GetMarkerAt(i, &mx, &my, &mz)) {
            char mName[32];
            snprintf(mName, sizeof(mName), "Marker #%u", (unsigned)(i + 1));
            if (strstr(mName, query) != NULL || strcmp(mName, query) == 0) {
                g_lua_pushnumber_1013c994(L, (double)mx);
                g_lua_pushnumber_1013c994(L, (double)my);
                g_lua_pushnumber_1013c994(L, (double)mz);
                return 3;
            }
        }
    }
    return 0;
}

static int NRTH_CDECL LuaApi_SyncPosition_10010ad0(void *L)
{
    if (!L || !g_lua_gettop_1013c990 || !g_lua_tonumber_1013c98c) {
        return 0;
    }
    int nargs = g_lua_gettop_1013c990(L);
    int base  = 0;
    if (g_lua_type_1013c988 && nargs >= 1 && g_lua_type_1013c988(L, 1) != 3) {
        base = 1;
    }
    if (nargs >= base + 3) {
        g_WeaponAimSync.fAimX = (float)g_lua_tonumber_1013c98c(L, base + 1);
        g_WeaponAimSync.fAimY = (float)g_lua_tonumber_1013c98c(L, base + 2);
        g_WeaponAimSync.fAimZ = (float)g_lua_tonumber_1013c98c(L, base + 3);
    }
    return 0;
}

static int NRTH_CDECL LuaApi_SyncVelocity_10010ba0(void *L)
{
    (void)L;
    return 0;
}

static void RegisterLuaApi_10010ff0(void *L)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    if (!L || !g_lua_createtable_1013c9a0 || !g_lua_pushcclosure_1013c984 ||
        !g_lua_setfield_1013c9a4) {
        return;
    }
    if (!Nrth_IsPointerReadable_VirtualQuery((const void *)g_lua_createtable_1013c9a0) ||
        !Nrth_IsPointerReadable_VirtualQuery((const void *)g_lua_pushcclosure_1013c984) ||
        !Nrth_IsPointerReadable_VirtualQuery((const void *)g_lua_setfield_1013c9a4)) {
        return;
    }
    const int LUA_GLOBALSINDEX_51 = -10002;
    g_lua_createtable_1013c9a0(L, 0, 6);
    g_lua_pushcclosure_1013c984(L, &LuaApi_StoppedResources_1000f920, 0);
    g_lua_setfield_1013c9a4(L, -2, "StoppedResources");
    g_lua_pushcclosure_1013c984(L, &LuaApi_ShootBullet_1000fe90, 0);
    g_lua_setfield_1013c9a4(L, -2, "ShootBullet");
    g_lua_pushcclosure_1013c984(L, &LuaApi_GetMarkersPos_10010cc0, 0);
    g_lua_setfield_1013c9a4(L, -2, "getMarkersPos");
    g_lua_createtable_1013c9a0(L, 0, 2);
    g_lua_pushcclosure_1013c984(L, &LuaApi_SyncPosition_10010ad0, 0);
    g_lua_setfield_1013c9a4(L, -2, "position");
    g_lua_pushcclosure_1013c984(L, &LuaApi_SyncVelocity_10010ba0, 0);
    g_lua_setfield_1013c9a4(L, -2, "velocity");
    g_lua_setfield_1013c9a4(L, -2, "sync");
    g_lua_setfield_1013c9a4(L, LUA_GLOBALSINDEX_51, "api");
#else
    (void)L;
    (void)g_pClientGame_10148ee8;
    (void)g_ClientIfaces_10148ed4;
    (void)g_ResourceMgr_1013c948;
    (void)s_activeResources;
    (void)s_activeResourceCount;
    (void)&LuaApi_StoppedResources_1000f920;
    (void)&LuaApi_ShootBullet_1000fe90;
    (void)&LuaApi_GetMarkersPos_10010cc0;
    (void)&LuaApi_SyncPosition_10010ad0;
    (void)&LuaApi_SyncVelocity_10010ba0;
#endif
}

static void ExtractVmLabelFromChunkName(const char *chunkName, char *outBuf, size_t outCap)
{
    if (!outBuf || outCap == 0) return;
    outBuf[0] = '\0';
    if (!chunkName || !chunkName[0]) return;
    const char *p = chunkName;
    while (*p == '@' || *p == '=' || *p == ':' || *p == '\\' || *p == '/') ++p;
    size_t n = 0;
    while (p[n] && p[n] != '\\' && p[n] != '/' && p[n] != '.' && n + 1 < outCap) {
        outBuf[n] = p[n];
        ++n;
    }
    outBuf[n] = '\0';
}

static void RecordLuaVmAndRunPending(void *L, const char *chunkNameHint = NULL)
{
    if (!L || !Nrth_IsPointerReadable_VirtualQuery(L)) {
        return;
    }
    g_LuaVmBridge.default_L_1013c95c = L;
    bool already = false;
    for (uint32_t i = 0; i < g_LuaVmBridge.slotCount && i < NRTH_VM_REGISTRY_CAP; ++i) {
        if (g_LuaVmBridge.registry_1013bf04[i].luaStatePtr32 == (uint32_t)(uintptr_t)L) {
            if (chunkNameHint && !g_LuaVmBridge.registry_1013bf04[i].resourceMeta[0]) {
                ExtractVmLabelFromChunkName(chunkNameHint,
                                            (char *)g_LuaVmBridge.registry_1013bf04[i].resourceMeta,
                                            sizeof(g_LuaVmBridge.registry_1013bf04[i].resourceMeta));
            }
            already = true;
            break;
        }
    }
    if (!already && g_LuaVmBridge.slotCount < NRTH_VM_REGISTRY_CAP) {
        uint32_t idx = g_LuaVmBridge.slotCount++;
        g_LuaVmBridge.registry_1013bf04[idx].luaStatePtr32 = (uint32_t)(uintptr_t)L;
        if (chunkNameHint) {
            ExtractVmLabelFromChunkName(chunkNameHint,
                                        (char *)g_LuaVmBridge.registry_1013bf04[idx].resourceMeta,
                                        sizeof(g_LuaVmBridge.registry_1013bf04[idx].resourceMeta));
        }
        RegisterLuaApi_10010ff0(L);
    }
    if (g_LuaVmBridge.execFlag_1013c939 &&
        g_LuaVmBridge.loadbuffer_1013c94c &&
        g_LuaVmBridge.pcall_1013c974) {
        static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
        static bool s_customGate = false;
        const char *chunkName = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                                0x2D, s_customChunk, &s_customGate);
        size_t slen = strlen(g_LuaVmBridge.scriptBuf_1013beec);
        if (slen > 0 &&
            g_LuaVmBridge.loadbuffer_1013c94c(L, g_LuaVmBridge.scriptBuf_1013beec, slen, chunkName) == 0) {
            g_LuaVmBridge.pcall_1013c974(L, 0, 0, 0);
        }
        g_LuaVmBridge.execFlag_1013c939 = 0;
    }
}

#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

typedef void (__thiscall *PFN_Client_10002ff0)(void *, void *, void *, void *, void *, void *, void *);
typedef int  (__cdecl    *PFN_Client_100047b0)(void *, const char *, size_t, const char *);
typedef unsigned char (__cdecl *PFN_Client_100050a0)(void *, const char *, void *, void *, void *, void *, float);
typedef void *(__thiscall *PFN_Client_10005290)(void *, void *, void *, void *, void *, void *, void *, void *);
typedef void *(__thiscall *PFN_Client_100052b0)(void *, void *, const char *, void *, void *, void *, void *, void *);
typedef void (__thiscall *PFN_Client_10005620)(void *, void *);
typedef int  (__thiscall *PFN_Client_100056c0)(void *, void *, void *, void *, void *, void *, void *, void *, void *);
typedef unsigned char (__cdecl *PFN_Client_100056f0)(void *, void *, void *);
typedef void (__thiscall *PFN_Client_10005ab0)(void *, void *, float *, void *, float, void *, void *);
typedef int  (__thiscall *PFN_Client_10005b30)(void *, void *, void *);
typedef int  (__cdecl    *PFN_Client_10005b50)(void *);

extern NrthHookSlot g_ClientHooks_10005b80[NRTH_CLIENT_HOOK_COUNT];


static void __fastcall Hook_Client_10002ff0(void *thisPtr, void *edxUnused,
                                            void *a1, void *a2, void *a3, void *a4, void *a5, void *a6)
{
    (void)edxUnused;
    if (thisPtr && a1 && a2 && a3 && a4 && a5 && a6) {
        g_pClientGame_10148ee8     = thisPtr;
        g_ClientIfaces_10148ed4[0] = a1;
        g_ClientIfaces_10148ed4[1] = a2;
        g_ClientIfaces_10148ed4[2] = a3;
        g_ClientIfaces_10148ed4[3] = a4;
        g_ClientIfaces_10148ed4[4] = a5;
        g_ClientIfaces_10148ed4[5] = a6;
    }
    PFN_Client_10002ff0 orig = (PFN_Client_10002ff0)g_ClientHooks_10005b80[0].origTrampoline;
    if (orig) {
        orig(thisPtr, a1, a2, a3, a4, a5, a6);
    }
}


static int __cdecl Hook_Client_100047b0(void *L, const char *buff, size_t sz, const char *name)
{
    PFN_Client_100047b0 orig = (PFN_Client_100047b0)g_ClientHooks_10005b80[1].origTrampoline;
    if (orig && !g_LuaVmBridge.loadbuffer_1013c94c) {
        g_LuaVmBridge.loadbuffer_1013c94c = (PFN_NrthLuaLoadBuffer)orig;
    }
    RecordLuaVmAndRunPending(L, name);
    if (name && buff && sz > 0 && sz < 0xA00000u) {
        NrthUI_OnClientScriptLoaded(name, buff, sz);
    }
    if (orig) {
        return orig(L, buff, sz, name);
    }
    return 0;
}


static unsigned char __cdecl Hook_Client_100050a0(void *a1, const char *eventName,
                                                  void *a3, void *a4, void *a5, void *a6, float a7)
{
    if (eventName && Nrth_IsPointerReadable_VirtualQuery(eventName)) {
        if (NrthUI_ShouldBlockServerEvent(eventName)) {
            return 0;
        }
    }
    PFN_Client_100050a0 orig = (PFN_Client_100050a0)g_ClientHooks_10005b80[2].origTrampoline;
    if (orig) {
        return orig(a1, eventName, a3, a4, a5, a6, a7);
    }
    return 1;
}


static void *__fastcall Hook_Client_10005290(void *thisPtr, void *edxUnused,
                                             void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    (void)edxUnused;
    if (thisPtr) {
        g_ResourceMgr_1013c948 = thisPtr;
    }
    PFN_Client_10005290 orig = (PFN_Client_10005290)g_ClientHooks_10005b80[4].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, a2, a3, a4, a5, a6, a7);
    }
    return NULL;
}


static void *__fastcall Hook_Client_100052b0(void *thisPtr, void *edxUnused,
                                             void *a1, const char *resName, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    (void)edxUnused;
    PFN_Client_100052b0 orig = (PFN_Client_100052b0)g_ClientHooks_10005b80[5].origTrampoline;
    void *resPtr = orig ? orig(thisPtr, a1, resName, a3, a4, a5, a6, a7) : NULL;
    if (resPtr && resName && Nrth_IsPointerReadable_VirtualQuery(resName) && resName[0]) {
        bool exists = false;
        for (uint32_t i = 0; i < s_activeResourceCount; ++i) {
            if (strcmp(s_activeResources[i].name, resName) == 0) {
                s_activeResources[i].resPtr = resPtr;
                exists = true;
                break;
            }
        }
        if (!exists && s_activeResourceCount < 128) {
            strncpy(s_activeResources[s_activeResourceCount].name, resName, 63);
            s_activeResources[s_activeResourceCount].name[63] = '\0';
            s_activeResources[s_activeResourceCount].resPtr   = resPtr;
            ++s_activeResourceCount;
        }
        NrthUI_OnResourceStarted(resName);
    }
    return resPtr;
}


static void __fastcall Hook_Client_10005620(void *thisPtr, void *edxUnused, void *resPtr)
{
    (void)edxUnused;
    PFN_Client_10005620 orig = (PFN_Client_10005620)g_ClientHooks_10005b80[6].origTrampoline;
    if (orig) {
        orig(thisPtr, resPtr);
    }
    for (uint32_t i = 0; i < s_activeResourceCount; ++i) {
        if (s_activeResources[i].resPtr == resPtr) {
            for (uint32_t j = i; j + 1 < s_activeResourceCount; ++j) {
                s_activeResources[j] = s_activeResources[j + 1];
            }
            --s_activeResourceCount;
            break;
        }
    }
}


static int __fastcall Hook_Client_100056c0(void *thisPtr, void *edxUnused,
                                           void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    (void)edxUnused;
    if (g_ReportChannels.suppressReports) {
        ++g_ReportChannels.screenshotCount;
        NrthUI_PushToastNotification("Screenshot blocked!");
        return 0;
    }
    PFN_Client_100056c0 orig = (PFN_Client_100056c0)g_ClientHooks_10005b80[7].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    return 0;
}


static unsigned char __cdecl Hook_Client_100056f0(void *a1, void *a2, void *a3)
{
    const char *eventName = (const char *)a1;
    if (eventName && Nrth_IsPointerReadable_VirtualQuery(eventName)) {
        if (NrthUI_ShouldBlockServerEvent(eventName)) {
            return 0;
        }
    }
    PFN_Client_100056f0 orig = (PFN_Client_100056f0)g_ClientHooks_10005b80[3].origTrampoline;
    if (orig) {
        return orig(a1, a2, a3);
    }
    return 1;
}


static void __fastcall Hook_Client_10005ab0(void *thisPtr, void *edxUnused,
                                            void *a1, float *posVec3, void *a3, float a4, void *a5, void *a6)
{
    (void)edxUnused;
    PFN_Client_10005ab0 orig = (PFN_Client_10005ab0)g_ClientHooks_10005b80[8].origTrampoline;
    if (!orig) {
        return;
    }
    float localVec[3] = { 0.0f, 0.0f, 0.0f };
    if (posVec3) {
        localVec[0] = posVec3[0];
        localVec[1] = posVec3[1];
        localVec[2] = posVec3[2];
    }

    if (g_PlayerHealthSync.bCrasher) {
        localVec[0] = 4294967296.0f;
        localVec[1] = 4294967296.0f;
        localVec[2] = 4294967296.0f;
    }
    orig(thisPtr, a1, posVec3 ? localVec : posVec3, a3, a4, a5, a6);
}


static int __fastcall Hook_Client_10005b30(void *thisPtr, void *edxUnused, void *a1, void *a2)
{
    (void)edxUnused;
    PFN_Client_10005b30 orig = (PFN_Client_10005b30)g_ClientHooks_10005b80[9].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, a2);
    }
    return 0;
}


static int __cdecl Hook_Client_10005b50(void *a1)
{
    if (g_ReportChannels.suppressReports) {
        ++g_ReportChannels.screenshotCount;
        NrthUI_PushToastNotification("Screenshot blocked!");
        return 0;
    }
    PFN_Client_10005b50 orig = (PFN_Client_10005b50)g_ClientHooks_10005b80[10].origTrampoline;
    if (orig) {
        return orig(a1);
    }
    return 0;
}

#else

typedef int (*PFN_GenericHook)(void *a1, void *a2, void *a3, void *a4);
static int DispatchClientHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4);

static int Hook_Client_10002ff0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(0,  a1, a2, a3, a4); }
static int Hook_Client_100047b0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(1,  a1, a2, a3, a4); }
static int Hook_Client_100050a0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(2,  a1, a2, a3, a4); }
static int Hook_Client_10005290(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(4,  a1, a2, a3, a4); }
static int Hook_Client_100052b0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(5,  a1, a2, a3, a4); }
static int Hook_Client_10005620(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(6,  a1, a2, a3, a4); }
static int Hook_Client_100056c0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(7,  a1, a2, a3, a4); }
static int Hook_Client_100056f0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(3,  a1, a2, a3, a4); }
static int Hook_Client_10005ab0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(8,  a1, a2, a3, a4); }
static int Hook_Client_10005b30(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(9,  a1, a2, a3, a4); }
static int Hook_Client_10005b50(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(10, a1, a2, a3, a4); }

#endif


NrthHookSlot g_ClientHooks_10005b80[NRTH_CLIENT_HOOK_COUNT] = {
    {  0, 0x10002ff0u, 0x10005c07u, 0x2Du, NULL, (void *)&Hook_Client_10002ff0, NULL, NULL, false },
    {  1, 0x100047b0u, 0x10005d28u, 0x2Du, NULL, (void *)&Hook_Client_100047b0, NULL, NULL, false },
    {  2, 0x100050a0u, 0x10005e54u, 0x2Du, NULL, (void *)&Hook_Client_100050a0, NULL, NULL, false },
    {  3, 0x100056f0u, 0x10005f56u, 0x2Du, NULL, (void *)&Hook_Client_100056f0, NULL, NULL, false },
    {  4, 0x10005290u, 0x10006050u, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B D9 89 5D ? 68 ? ? ? ? E8 ? ? ? ? 83 C4",
       (void *)&Hook_Client_10005290, NULL, NULL, false },
    {  5, 0x100052b0u, 0x10006140u, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F9 89 7D ? 89 7D ? 0F B7 45",
       (void *)&Hook_Client_100052b0, NULL, NULL, false },
    {  6, 0x10005620u, 0x10006230u, 0x2Du, NULL, (void *)&Hook_Client_10005620, NULL, NULL, false },
    {  7, 0x100056c0u, 0x1000633bu, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 4D ? 8B 45 ? 89 45 ? 8B 45",
       (void *)&Hook_Client_100056c0, NULL, NULL, false },
    {  8, 0x10005ab0u, 0x10006450u, 0x2Du, NULL, (void *)&Hook_Client_10005ab0, NULL, NULL, false },
    {  9, 0x10005b30u, 0x1000657bu, 0x2Du, NULL, (void *)&Hook_Client_10005b30, NULL, NULL, false },
    { 10, 0x10005b50u, 0x10006684u, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 7D ? 8D 8D ? ? ? ? 57 C7 85 ? ? ? ? 00 00 00 00 C7 85 ? ? ? ? 00 00 00 00 E8",
       (void *)&Hook_Client_10005b50, NULL, NULL, false },
};

#if !defined(_WIN32) || defined(NRTH_HEADLESS_TEST)
static int DispatchClientHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4)
{
    if (slotIdx == 0 && a1 && Nrth_IsPointerReadable_VirtualQuery(a1)) {
        RecordLuaVmAndRunPending(a1);
    }
    if (slotIdx < NRTH_CLIENT_HOOK_COUNT && g_ClientHooks_10005b80[slotIdx].origTrampoline) {
        PFN_GenericHook orig = (PFN_GenericHook)g_ClientHooks_10005b80[slotIdx].origTrampoline;
        return orig(a1, a2, a3, a4);
    }
    return 0;
}
#endif





static int DispatchNetcHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4);

static int Hook_Netc_1001dd30(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(0, a1, a2, a3, a4); }
static int Hook_Netc_1001dd90(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(1, a1, a2, a3, a4); }
static int Hook_Netc_1001df90(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(2, a1, a2, a3, a4); }
static int Hook_Netc_1001fa80(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(3, a1, a2, a3, a4); }

static NrthHookSlot g_NetcHooks_10020640[NRTH_NETC_HOOK_COUNT] = {
    { 0, 0x1001dd30u, 0x10023670u, 0x2Du, NULL, (void *)&Hook_Netc_1001dd30, NULL, NULL, false },
    { 1, 0x1001dd90u, 0x10023530u, 0x2Du,
      "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 45 ? 0F 57 C0 89 85 ? ? ? ? 33 FF",
      (void *)&Hook_Netc_1001dd90, NULL, NULL, false },
    { 2, 0x1001df90u, 0x100233f0u, 0x2Du,
      "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 8D ? ? ? ? C7 85",
      (void *)&Hook_Netc_1001df90, NULL, NULL, false },
    { 3, 0x1001fa80u, 0x100232b0u, 0x2Du,
      "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B 4D ? 8D 51 ? ? ? ? ? ? 41 84 C0 75 ? 2B CA 83 F9",
      (void *)&Hook_Netc_1001fa80, NULL, NULL, false },
};

static int DispatchNetcHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4)
{
    switch (slotIdx) {
    case 0: ++g_ReportChannels.screenshotCount;    break;
    case 1: ++g_ReportChannels.transgressionCount; break;
    case 2: ++g_ReportChannels.diagnosticCount;    break;
    case 3: ++g_ReportChannels.acinfoCount;        break;
    default: break;
    }
    if (g_ReportChannels.suppressReports && slotIdx < 3) {
        return 0;
    }
    if (slotIdx < NRTH_NETC_HOOK_COUNT && g_NetcHooks_10020640[slotIdx].origTrampoline) {
        typedef int (*PFN_NetcGeneric)(void *, void *, void *, void *);
        PFN_NetcGeneric orig = (PFN_NetcGeneric)g_NetcHooks_10020640[slotIdx].origTrampoline;
        return orig(a1, a2, a3, a4);
    }
    return 0;
}




extern "C" uint32_t ArmClient_10005b80(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours)
{
    static const struct { uint32_t slot; uint32_t sigId; } kClientSigMap[7] = {
        { 0, 10 },
        { 1,  5 },
        { 2,  3 },
        { 3, 15 },
        { 6,  6 },
        { 8, 13 },
        { 9, 19 },
    };
    for (uint32_t i = 0; i < 7; ++i) {
        g_ClientHooks_10005b80[kClientSigMap[i].slot].pattern =
            DecryptCatalogSig(kClientSigMap[i].sigId);
    }

    uint32_t hooked = 0;
    for (uint32_t i = 0; i < NRTH_CLIENT_HOOK_COUNT; ++i) {
        NrthHookSlot &slot = g_ClientHooks_10005b80[i];
        const uint8_t *hit = ResolvePattern_10002960(moduleBase, moduleSize, slot.pattern);
        slot.targetAddr = (void *)hit;
        if (!hit) {
            continue;
        }
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
        if (applyDetours) {
            if (MH_CreateHook(slot.targetAddr, slot.detourFn, &slot.origTrampoline) == MH_OK &&
                MH_EnableHook(slot.targetAddr) == MH_OK) {
                slot.installed = true;
                if (i == 1 && slot.origTrampoline) {
                    g_LuaVmBridge.loadbuffer_1013c94c = (PFN_NrthLuaLoadBuffer)slot.origTrampoline;
                }
                ++g_TotalInstalledHooks;
                ++hooked;
            }
        }
#else
        if (applyDetours) {
            uint8_t *fn = (uint8_t *)slot.targetAddr;
            fn[0] = 0xE9u;
            int32_t rel = (int32_t)((slot.handlerVa - 0x10000000u) -
                                    ((uint32_t)(fn - moduleBase) + 5u));
            fn[1] = (uint8_t)(rel & 0xFF);
            fn[2] = (uint8_t)((rel >> 8) & 0xFF);
            fn[3] = (uint8_t)((rel >> 16) & 0xFF);
            fn[4] = (uint8_t)((rel >> 24) & 0xFF);
            slot.installed = true;
            ++g_TotalInstalledHooks;
            ++hooked;
        }
#endif
    }
    return hooked;
}




static uintptr_t g_ClientResolvedOffsets[NRTH_CLIENT_RESOLVE_COUNT] = {0};

extern "C" uint32_t ResolveClientOffsets_1000c390(const uint8_t *moduleBase, uint32_t moduleSize)
{

    const char *scanPatterns[NRTH_CLIENT_RESOLVE_COUNT] = {

        DecryptCatalogSig(4),

        DecryptCatalogSig(11),

        DecryptCatalogSig(14),

        "55 8B EC 56 FF 75 ? 8B 75 ? 56 E8 ? ? ? ? 8B C8",

        "55 8B EC 57 8B 7D ? 8B 4F ? 8B 41 ? 3B 41 ? 72 ? 57 E8 ? ? ? ? 83 C4 ? 56 FF 75 ? 8B 77 ? FF 75 ? 57 E8 ? ? ? ? ? ? 83 C4 ? C7 46 ? ? ? ? ? 8B 4F ? 8B 47 ? 5E 3B 41 ? 72 ? C7 05 ? ? ? ? ? ? ? ? 83 47 ? ? 5F 5D C3 ? ? ? ? ? ? ? ? ? ? ? ? 55 8B EC 8B 4D",

        DecryptCatalogSig(1),

        DecryptCatalogSig(9),

        DecryptCatalogSig(8),

        "55 8B EC 56 57 FF 75 ? 8B 7D",

        "55 8B EC 83 EC ? 56 8B 75 ? 57 FF 75",

        DecryptCatalogSig(12),

        "55 8B EC 8B 55 ? 8B 42 ? C7 40",

        DecryptCatalogSig(2),

        DecryptCatalogSig(17),

        "55 8B EC 57 FF 75 ? 8B 7D ? 57 E8 ? ? ? ? 83 C4 ? 83 78",

        "55 8B EC 53 57 8B 7D ? 8B 47 ? 2B 47 ? 83 E0 ? 83 F8 ? 7D ? C7 05 ? ? ? ? ? ? ? ? FF 75 ? 57 E8 ? ? ? ? 8B D8 83 C4 ? 83 7B ? ? 74 ? C7 05 ? ? ? ? ? ? ? ? 56 FF 75",

        DecryptCatalogSig(7),

        DecryptCatalogSig(20),

        DecryptCatalogSig(18),

        "55 8B EC 8B 55 ? F2 0F 10 45"
    };

    uint32_t resolved = 0;
    for (uint32_t i = 0; i < NRTH_CLIENT_RESOLVE_COUNT; ++i) {
        const uint8_t *hit = ResolvePattern_10002960(moduleBase, moduleSize, scanPatterns[i]);
        g_ClientResolvedOffsets[i] = (uintptr_t)hit;
        if (hit) {
            ++resolved;
        }
    }


    g_lua_pushcclosure_1013c984 = (PFN_lua_pushcclosure_t)g_ClientResolvedOffsets[0];
    g_lua_setfield_1013c9a4     = (PFN_lua_setfield_t)g_ClientResolvedOffsets[1];
    g_lua_gettop_1013c990       = (PFN_lua_gettop_t)g_ClientResolvedOffsets[2];
    g_lua_tolstring_1013c980    = (PFN_lua_tolstring_t)g_ClientResolvedOffsets[3];
    g_lua_createtable_1013c9a0  = (PFN_lua_createtable_t)g_ClientResolvedOffsets[4];
    g_lua_tonumber_1013c98c     = (PFN_lua_tonumber_t)g_ClientResolvedOffsets[5];
    g_lua_type_1013c988         = (PFN_lua_type_t)g_ClientResolvedOffsets[7];
    g_lua_pcall_1013c974        = (PFN_lua_pcall_t)g_ClientResolvedOffsets[10];
    if (g_lua_pcall_1013c974) {
        g_LuaVmBridge.pcall_1013c974 = (PFN_NrthLuaPcall)g_lua_pcall_1013c974;
    }
    g_lua_settop_1013c99c       = (PFN_lua_settop_t)g_ClientResolvedOffsets[13];
    g_lua_rawgeti_1013c9a8      = (PFN_lua_rawgeti_t)g_ClientResolvedOffsets[14];
    g_lua_rawseti_1013c97c      = (PFN_lua_rawseti_t)g_ClientResolvedOffsets[15];
    g_lua_objlen_1013c978       = (PFN_lua_objlen_t)g_ClientResolvedOffsets[16];
    g_lua_pushstring_1013c998   = (PFN_lua_pushstring_t)g_ClientResolvedOffsets[18];
    g_lua_pushnumber_1013c994   = (PFN_lua_pushnumber_t)g_ClientResolvedOffsets[19];

    return resolved;
}





extern "C" uint32_t ArmNetc_10020640(uint8_t *moduleBase, uint32_t moduleSize,
                                     bool applyDetours, bool applyPatches)
{
    const char *netcPatterns[NRTH_NETC_SCAN_COUNT] = {
        DecryptCatalogSig(16),
        g_NetcHooks_10020640[1].pattern,
        g_NetcHooks_10020640[2].pattern,
        g_NetcHooks_10020640[3].pattern,
        "55 8B EC 83 EC ? 56 8B 75 ? 83 7E ? 00 75 ?",
        "55 8B EC 56 8B 75 ? 57 8B 7D ? 8B C6 2B C7"
    };
    g_NetcHooks_10020640[0].pattern = netcPatterns[0];

    uint8_t *scanHits[NRTH_NETC_SCAN_COUNT] = {NULL};
    for (uint32_t i = 0; i < NRTH_NETC_SCAN_COUNT; ++i) {
        scanHits[i] = (uint8_t *)ResolvePattern_10002960(moduleBase, moduleSize, netcPatterns[i]);
    }

    uint32_t actions = 0;

    for (uint32_t i = 0; i < NRTH_NETC_HOOK_COUNT; ++i) {
        NrthHookSlot &slot = g_NetcHooks_10020640[i];
        slot.targetAddr = scanHits[i];
        if (!slot.targetAddr) {
            continue;
        }
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
        if (applyDetours) {
            if (MH_CreateHook(slot.targetAddr, slot.detourFn, &slot.origTrampoline) == MH_OK &&
                MH_EnableHook(slot.targetAddr) == MH_OK) {
                slot.installed = true;
                ++g_TotalInstalledHooks;
                ++actions;
            }
        }
#else
        if (applyDetours) {
            slot.installed = true;
            ++g_TotalInstalledHooks;
            ++actions;
        }
#endif
    }

    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        uint8_t opcode = 0xC3u;
        uint32_t prepVa = g_PatchList_101493e4[i].prepVa;
        uint32_t callVa = g_PatchList_101493e4[i].callVa;
        uint32_t patGlb = g_PatchList_101493e4[i].patternGlobal;
        void *target    = applyPatches ? (void *)scanHits[i] : NULL;
        if (PatchByte_10011870(target, opcode, prepVa, callVa, patGlb)) {
            ++actions;
        }
    }

    return actions;
}







extern "C" void **FindD3D9VTableInBuffer_10012980(const uint8_t *base, uint32_t size)
{
    static const char *kD3D9VTablePat = "C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86";
    if (!base || size < 16) {
        return NULL;
    }
    uint8_t bytes[32], mask[32];
    uint32_t plen = nrth_compile_pat(kD3D9VTablePat, bytes, mask, 32);
    if (plen == 0 || plen > size) {
        return NULL;
    }
    for (uint32_t i = 0; i + plen <= size; ++i) {
        if (base[i] != 0xC7u || base[i + 1] != 0x06u) continue;
        bool ok = true;
        for (uint32_t j = 0; j < plen; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            uint32_t vtAddr32 = (uint32_t)base[i + 2] |
                                ((uint32_t)base[i + 3] << 8) |
                                ((uint32_t)base[i + 4] << 16) |
                                ((uint32_t)base[i + 5] << 24);
            return (void **)(uintptr_t)vtAddr32;
        }
    }
    return NULL;
}




extern "C" const NrthHookSlot *Nrth_GetClientHookTable(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_CLIENT_HOOK_COUNT;
    return g_ClientHooks_10005b80;
}

extern "C" const NrthHookSlot *Nrth_GetNetcHookTable(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_NETC_HOOK_COUNT;
    return g_NetcHooks_10020640;
}

extern "C" const NrthPatchRecord *Nrth_GetPatchList_101493e4(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_NETC_PATCH_COUNT;
    return g_PatchList_101493e4;
}

extern "C" const uintptr_t *Nrth_GetClientResolvedOffsets(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_CLIENT_RESOLVE_COUNT;
    return g_ClientResolvedOffsets;
}

extern "C" uint32_t Nrth_GetTotalPatternScans(void)
{
    return g_TotalPatternScans;
}

extern "C" uint32_t Nrth_GetTotalInstalledHooks(void)
{
    return g_TotalInstalledHooks;
}

extern "C" uint32_t Nrth_GetTotalAppliedPatches(void)
{
    return g_TotalAppliedPatches;
}

extern "C" void Nrth_ResetArmingCounters(void)
{
    g_TotalPatternScans   = 0;
    g_TotalInstalledHooks = 0;
    g_TotalAppliedPatches = 0;
    for (uint32_t i = 0; i < NRTH_CLIENT_HOOK_COUNT; ++i) {
        g_ClientHooks_10005b80[i].targetAddr = NULL;
        g_ClientHooks_10005b80[i].installed  = false;
    }
    for (uint32_t i = 0; i < NRTH_NETC_HOOK_COUNT; ++i) {
        g_NetcHooks_10020640[i].targetAddr = NULL;
        g_NetcHooks_10020640[i].installed  = false;
    }
    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        g_PatchList_101493e4[i].targetAddr = NULL;
        g_PatchList_101493e4[i].origByte   = 0;
        g_PatchList_101493e4[i].applied    = 0;
    }
    memset(g_ClientResolvedOffsets, 0, sizeof(g_ClientResolvedOffsets));
}




#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
static bool IsAddressWritable(const void *ptr, size_t len)
{
    if (!ptr || len == 0) {
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    DWORD writableMask = PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & writableMask) == 0 || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    return true;
}

static bool IsAddressExecutable(const void *ptr)
{
    if (!ptr) {
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    DWORD execMask = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & execMask) == 0 || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    return true;
}

static uintptr_t GetLocalPed_00B6F5F0(void)
{
    const uintptr_t *ppPed = (const uintptr_t *)(uintptr_t)0x00B6F5F0u;
    if (Nrth_IsPointerReadable_VirtualQuery(ppPed)) {
        uintptr_t pPed = *ppPed;
        if (pPed >= 0x10000u && Nrth_IsPointerReadable_VirtualQuery((const void *)pPed)) {
            return pPed;
        }
    }
    return 0;
}

static uintptr_t GetCurrentVehicle_00BA18FC(void)
{
    const uintptr_t *ppVeh = (const uintptr_t *)(uintptr_t)0x00BA18FCu;
    if (Nrth_IsPointerReadable_VirtualQuery(ppVeh)) {
        uintptr_t pVeh = *ppVeh;
        if (pVeh >= 0x10000u && Nrth_IsPointerReadable_VirtualQuery((const void *)pVeh)) {
            return pVeh;
        }
    }
    uintptr_t pPed = GetLocalPed_00B6F5F0();
    if (pPed && Nrth_IsPointerReadable_VirtualQuery((const void *)(pPed + 0x58Cu))) {
        uintptr_t pVeh = *(const uintptr_t *)(pPed + 0x58Cu);
        if (pVeh >= 0x10000u && Nrth_IsPointerReadable_VirtualQuery((const void *)pVeh)) {
            return pVeh;
        }
    }
    return 0;
}
#endif




extern "C" void Nrth_AirbreakTick_10001d80(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    if (!g_PlayerHealthSync.bAirBreak) {
        return;
    }

    uintptr_t pEntity = GetCurrentVehicle_00BA18FC();
    if (!pEntity) {
        pEntity = GetLocalPed_00B6F5F0();
    }
    if (!pEntity || !Nrth_IsPointerReadable_VirtualQuery((const void *)(pEntity + 0x14u))) {
        return;
    }

    uintptr_t pMatrix = *(const uintptr_t *)(pEntity + 0x14u);
    if (!pMatrix || !IsAddressWritable((const void *)(pMatrix + 0x30u), 12)) {
        return;
    }

    float camHeading = 0.0f;
    const float *pCamHeading = (const float *)(uintptr_t)0x00B6F258u;
    if (Nrth_IsPointerReadable_VirtualQuery(pCamHeading)) {
        camHeading = *pCamHeading;
    }

    float speed = g_PlayerHealthSync.fAirBreakSpeed > 0.01f
                      ? g_PlayerHealthSync.fAirBreakSpeed
                      : 1.0f;
    float step = speed * 0.25f;
    if (GetAsyncKeyState(VK_LSHIFT) & 0x8000) {
        step *= (1.0f + (g_PlayerHealthSync.fAirBreakIncr > 0.0f ? g_PlayerHealthSync.fAirBreakIncr : 0.5f));
    }

    float dx = 0.0f, dy = 0.0f, dz = 0.0f;

    float fwdX = -cosf(camHeading);
    float fwdY = -sinf(camHeading);
    float rightX = sinf(camHeading);
    float rightY = -cosf(camHeading);

    if (GetAsyncKeyState('W') & 0x8000) { dx += fwdX * step;   dy += fwdY * step; }
    if (GetAsyncKeyState('S') & 0x8000) { dx -= fwdX * step;   dy -= fwdY * step; }
    if (GetAsyncKeyState('D') & 0x8000) { dx += rightX * step; dy += rightY * step; }
    if (GetAsyncKeyState('A') & 0x8000) { dx -= rightX * step; dy -= rightY * step; }
    if (GetAsyncKeyState(VK_SPACE) & 0x8000)    { dz += step; }
    if (GetAsyncKeyState(VK_LCONTROL) & 0x8000) { dz -= step; }

    float *pPos = (float *)(pMatrix + 0x30u);
    pPos[0] += dx;
    pPos[1] += dy;
    pPos[2] += dz;


    if (IsAddressWritable((void *)(pEntity + 0x44u), 28)) {
        float *pMove = (float *)(pEntity + 0x44u);
        pMove[0] = 0.0f;
        pMove[1] = 0.0f;
        pMove[2] = 0.0f;
        float *pTurn = (float *)(pEntity + 0x54u);
        pTurn[0] = 0.0f;
        pTurn[1] = 0.0f;
        pTurn[2] = 0.0f;
    }
#endif
}


extern "C" void Nrth_TriggerAllWeapons_1002a5a7(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    if (!GetLocalPed_00B6F5F0()) {
        return;
    }
    typedef void (__cdecl *PFN_CWeaponCheat)(void);
    PFN_CWeaponCheat fn = (PFN_CWeaponCheat)(uintptr_t)0x004385B0u;
    if (IsAddressExecutable((const void *)fn)) {
        fn();
    }
#endif
}


extern "C" void Nrth_TriggerJetpack_1002a86c(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    if (!GetLocalPed_00B6F5F0()) {
        return;
    }
    typedef void (__cdecl *PFN_CJetpackCheat)(void);
    PFN_CJetpackCheat fn = (PFN_CJetpackCheat)(uintptr_t)0x00439600u;
    if (IsAddressExecutable((const void *)fn)) {
        fn();
    }
#endif
}


extern "C" bool Nrth_RepairCurrentVehicle_1002f070(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pVeh = GetCurrentVehicle_00BA18FC();
    if (!pVeh) {
        return false;
    }
    if (IsAddressWritable((void *)(pVeh + 0x4C0u), sizeof(float))) {
        *(float *)(pVeh + 0x4C0u) = 1000.0f;
        return true;
    }
#endif
    return false;
}


extern "C" bool Nrth_StartCurrentVehicleEngine_1002f0f0(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pVeh = GetCurrentVehicle_00BA18FC();
    if (!pVeh) {
        return false;
    }
    if (IsAddressWritable((void *)(pVeh + 0x428u), 1)) {
        *(uint8_t *)(pVeh + 0x428u) |= 0x10u;
        return true;
    }
#endif
    return false;
}


extern "C" bool Nrth_UnlockNearestVehicle_1002eea0(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pVeh = GetCurrentVehicle_00BA18FC();
    if (pVeh && IsAddressWritable((void *)(pVeh + 0x4F8u), sizeof(uint32_t))) {
        *(uint32_t *)(pVeh + 0x4F8u) = 1u;
        return true;
    }
#endif
    return false;
}


extern "C" bool Nrth_StopCurrentVehicle(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pVeh = GetCurrentVehicle_00BA18FC();
    if (pVeh && IsAddressWritable((void *)(pVeh + 0x44u), 28)) {
        float *pMove = (float *)(pVeh + 0x44u);
        pMove[0] = 0.0f;
        pMove[1] = 0.0f;
        pMove[2] = 0.0f;
        float *pTurn = (float *)(pVeh + 0x54u);
        pTurn[0] = 0.0f;
        pTurn[1] = 0.0f;
        pTurn[2] = 0.0f;
        return true;
    }
#endif
    return false;
}


extern "C" bool Nrth_DestroyCurrentVehicle(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pVeh = GetCurrentVehicle_00BA18FC();
    if (pVeh && IsAddressWritable((void *)(pVeh + 0x4C0u), sizeof(float))) {
        *(float *)(pVeh + 0x4C0u) = 0.0f;
        return true;
    }
#endif
    return false;
}

extern "C" bool Nrth_GetLocalPlayerPosition(float *outX, float *outY, float *outZ)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pEntity = GetCurrentVehicle_00BA18FC();
    if (!pEntity) {
        pEntity = GetLocalPed_00B6F5F0();
    }
    if (!pEntity || !Nrth_IsPointerReadable_VirtualQuery((const void *)(pEntity + 0x14u))) {
        return false;
    }
    uintptr_t pMatrix = *(const uintptr_t *)(pEntity + 0x14u);
    if (!pMatrix || !Nrth_IsPointerReadable_VirtualQuery((const void *)(pMatrix + 0x30u))) {
        return false;
    }
    const float *pPos = (const float *)(pMatrix + 0x30u);
    if (outX) *outX = pPos[0];
    if (outY) *outY = pPos[1];
    if (outZ) *outZ = pPos[2];
    return true;
#else
    (void)outX; (void)outY; (void)outZ;
    return false;
#endif
}

extern "C" bool Nrth_TeleportLocalPlayer(float x, float y, float z)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    uintptr_t pEntity = GetCurrentVehicle_00BA18FC();
    if (!pEntity) {
        pEntity = GetLocalPed_00B6F5F0();
    }
    if (!pEntity || !Nrth_IsPointerReadable_VirtualQuery((const void *)(pEntity + 0x14u))) {
        return false;
    }
    uintptr_t pMatrix = *(const uintptr_t *)(pEntity + 0x14u);
    if (!pMatrix || !IsAddressWritable((const void *)(pMatrix + 0x30u), 12)) {
        return false;
    }
    float *pPos = (float *)(pMatrix + 0x30u);
    pPos[0] = x;
    pPos[1] = y;
    pPos[2] = z;
    if (IsAddressWritable((void *)(pEntity + 0x44u), 28)) {
        float *pMove = (float *)(pEntity + 0x44u);
        pMove[0] = 0.0f;
        pMove[1] = 0.0f;
        pMove[2] = 0.0f;
        float *pTurn = (float *)(pEntity + 0x54u);
        pTurn[0] = 0.0f;
        pTurn[1] = 0.0f;
        pTurn[2] = 0.0f;
    }
    return true;
#else
    (void)x; (void)y; (void)z;
    return false;
#endif
}




extern "C" bool Nrth_StopClientResource_100054a0(const char *resName)
{
    if (!resName || !resName[0]) {
        return false;
    }
    bool recorded = false;
    for (uint32_t i = 0; i < s_stoppedResourceCount; ++i) {
        if (strcmp(s_stoppedResources[i], resName) == 0) {
            recorded = true;
            break;
        }
    }
    if (!recorded && s_stoppedResourceCount < 128) {
        strncpy(s_stoppedResources[s_stoppedResourceCount], resName, 63);
        s_stoppedResources[s_stoppedResourceCount][63] = '\0';
        ++s_stoppedResourceCount;
    }
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
    for (uint32_t i = 0; i < s_activeResourceCount; ++i) {
        if (strcmp(s_activeResources[i].name, resName) == 0) {
            void *resPtr = s_activeResources[i].resPtr;
            PFN_Client_10005620 origRemove = (PFN_Client_10005620)g_ClientHooks_10005b80[6].origTrampoline;
            if (origRemove && g_ResourceMgr_1013c948 && resPtr) {
                origRemove(g_ResourceMgr_1013c948, resPtr);
            }
            for (uint32_t j = i; j + 1 < s_activeResourceCount; ++j) {
                s_activeResources[j] = s_activeResources[j + 1];
            }
            --s_activeResourceCount;
            return true;
        }
    }
#endif
    return true;
}


extern "C" void Nrth_TickGameFeatures_10015812(void)
{
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

    if (!g_pClientGame_10148ee8) {
        return;
    }

    uintptr_t pPed = GetLocalPed_00B6F5F0();
    if (!pPed) {
        return;
    }




    if (IsAddressWritable((void *)(uintptr_t)0x00969160u, 1)) {
        *(uint8_t *)(uintptr_t)0x00969160u = g_PlayerHealthSync.bDriveWater ? 1u : 0u;
    }
    if (IsAddressWritable((void *)(uintptr_t)0x00969152u, 1)) {
        *(uint8_t *)(uintptr_t)0x00969152u = g_PlayerHealthSync.bFlyingCar ? 1u : 0u;
    }


    if ((g_PlayerHealthSync.bGodMode || g_PlayerHealthSync.bGiveHp) &&
        IsAddressWritable((void *)(pPed + 0x540u), sizeof(float))) {
        float targetHp = g_PlayerHealthSync.fHealth > 0.0f ? g_PlayerHealthSync.fHealth : 100.0f;
        if (g_PlayerHealthSync.bGodMode && targetHp < 100.0f) {
            targetHp = 100.0f;
        }
        *(float *)(pPed + 0x540u) = targetHp;
    }
    if ((g_PlayerHealthSync.bGodMode || g_PlayerHealthSync.bGiveArmor) &&
        IsAddressWritable((void *)(pPed + 0x548u), sizeof(float))) {
        float targetAr = g_PlayerHealthSync.fArmor > 0.0f ? g_PlayerHealthSync.fArmor : 100.0f;
        if (g_PlayerHealthSync.bGodMode && targetAr < 100.0f) {
            targetAr = 100.0f;
        }
        *(float *)(pPed + 0x548u) = targetAr;
    }


    uintptr_t pVeh = GetCurrentVehicle_00BA18FC();
    if (pVeh) {
        if ((g_PlayerHealthSync.bVehGodMode || g_PlayerHealthSync.bRepairCar) &&
            IsAddressWritable((void *)(pVeh + 0x4C0u), sizeof(float))) {
            *(float *)(pVeh + 0x4C0u) = 1000.0f;
        }
        if (g_PlayerHealthSync.bStartEngine &&
            IsAddressWritable((void *)(pVeh + 0x428u), 1)) {
            *(uint8_t *)(pVeh + 0x428u) |= 0x10u;
        }
        if (g_PlayerHealthSync.bUnlockCar &&
            IsAddressWritable((void *)(pVeh + 0x4F8u), sizeof(uint32_t))) {
            *(uint32_t *)(pVeh + 0x4F8u) = 1u;
        }
        if (g_PlayerHealthSync.bFastStop && (GetAsyncKeyState(VK_SPACE) & 0x8000)) {
            Nrth_StopCurrentVehicle();
        }
    }


    if (g_PlayerHealthSync.bAirBreak) {
        Nrth_AirbreakTick_10001d80();
    }
#endif
}




#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

typedef LONG NTSTATUS;
typedef struct _NVX_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NVX_UNICODE_STRING;

typedef NTSTATUS (NTAPI  *PFN_LdrLoadDll)(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
typedef HRESULT  (WINAPI *PFN_Present)(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
typedef HRESULT  (WINAPI *PFN_Reset)(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
typedef IDirect3D9 *(WINAPI *PFN_Direct3DCreate9)(UINT);
typedef BOOL     (WINAPI *PFN_SetCursorPos)(int, int);
typedef int      (WINAPI *PFN_ShowCursor)(BOOL);
typedef BOOL     (WINAPI *PFN_ClipCursor)(const RECT *);

static PFN_LdrLoadDll   g_pOrigLdrLoadDll   = NULL;
static PFN_Present      g_pOrigPresent      = NULL;
static PFN_Reset        g_pOrigReset        = NULL;
static PFN_SetCursorPos g_pOrigSetCursorPos = NULL;
static PFN_ShowCursor   g_pOrigShowCursor   = NULL;
static PFN_ClipCursor   g_pOrigClipCursor   = NULL;

static volatile LONG    g_lClientArmed      = 0;
static volatile LONG    g_lNetcArmed        = 0;
static volatile LONG    g_lOverlayArmed     = 0;
static volatile LONG    g_lCursorArmed      = 0;
static bool             g_bOverlayInit      = false;
static bool             g_bMenuOpen         = false;
static ULONGLONG        g_lastToggleTick    = 0;
static POINT            g_savedCursorPos    = { 0, 0 };
static IDirect3DDevice9 *g_pDevice          = NULL;
static HWND             g_hGameWnd          = NULL;
static WNDPROC          g_pOrigWndProc      = NULL;

static DWORD WINAPI MainInitThread(LPVOID lpParam);
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
static void **GetD3D9DeviceVTable(void);
static bool InstallD3D9Hooks(void **vtable);
static void InstallCursorHooks_100165ee(void);
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
static LRESULT CALLBACK GameWndProc(HWND, UINT, WPARAM, LPARAM);
static void BuildOverlayMenu(void);
static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice, HWND hDestWindow);
static void UpdateOverlayInput(void);
static void ToggleMenuState(void);
static const char *BaseNameA(const char *path);
static uint32_t GetLoadedModuleSize(HMODULE hMod);
static void RunEnvironmentProbes(void);
static void TryArmLoadedModules(void);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);


        char hostExe[MAX_PATH] = {0};
        if (GetModuleFileNameA(NULL, hostExe, MAX_PATH) != 0) {
            const char *exeBase = BaseNameA(hostExe);
            if (_stricmp(exeBase, "NORTH LOADER.exe") == 0) {
                return TRUE;
            }
        }

        HMODULE hPinned = NULL;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCSTR)DllMain,
            &hPinned);

        HANDLE hThread = CreateThread(NULL, 0, MainInitThread, hModule, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}

static void RunEnvironmentProbes(void)
{
    CreateDirectoryA("C:\\NVX", NULL);
    CreateDirectoryA("C:\\NVX\\logs", NULL);
    CreateDirectoryA("C:\\NVX\\dump", NULL);

    static char s_adsBuf[sizeof(kCt_AdsNt2)] = {0};
    static bool s_adsGate = false;
    const char *adsPath = NrthDecryptOnce(kCt_AdsNt2, sizeof(kCt_AdsNt2), 0x20, s_adsBuf, &s_adsGate);
    HANDLE hAds = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hAds != INVALID_HANDLE_VALUE) {
        CloseHandle(hAds);
    }

    if (g_cfg.noSpoofer) {
        return;
    }

    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Multi Theft Auto: San Andreas All\\Common",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }

    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY spq;
        memset(&spq, 0, sizeof(spq));
        spq.PropertyId = StorageDeviceProperty;
        spq.QueryType  = PropertyStandardQuery;
        uint8_t outBuf[512] = {0};
        DWORD bytesRet = 0;
        DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                        &spq, sizeof(spq), outBuf, sizeof(outBuf), &bytesRet, NULL);
        CloseHandle(hDisk);
    }
}






static BOOL WINAPI Hooked_SetCursorPos(int X, int Y)
{
    if (g_bMenuOpen) {
        return TRUE;
    }
    return g_pOrigSetCursorPos ? g_pOrigSetCursorPos(X, Y) : TRUE;
}

static int WINAPI Hooked_ShowCursor(BOOL bShow)
{
    if (g_bMenuOpen) {
        return 1;
    }
    return g_pOrigShowCursor ? g_pOrigShowCursor(bShow) : (bShow ? 1 : -1);
}

static BOOL WINAPI Hooked_ClipCursor(const RECT *lpRect)
{
    if (g_bMenuOpen) {
        return TRUE;
    }
    return g_pOrigClipCursor ? g_pOrigClipCursor(lpRect) : TRUE;
}

static void InstallCursorHooks_100165ee(void)
{
    if (InterlockedCompareExchange(&g_lCursorArmed, 1, 0) != 0) {
        return;
    }
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        hUser32 = LoadLibraryA("user32.dll");
    }
    if (!hUser32) {
        InterlockedExchange(&g_lCursorArmed, 0);
        return;
    }
    FARPROC pSetCursorPos = GetProcAddress(hUser32, "SetCursorPos");
    FARPROC pShowCursor   = GetProcAddress(hUser32, "ShowCursor");
    FARPROC pClipCursor   = GetProcAddress(hUser32, "ClipCursor");

    if (pSetCursorPos) {
        if (MH_CreateHook((LPVOID)pSetCursorPos, (LPVOID)&Hooked_SetCursorPos,
                          (LPVOID *)&g_pOrigSetCursorPos) == MH_OK) {
            MH_EnableHook((LPVOID)pSetCursorPos);
        }
    }
    if (pShowCursor) {
        if (MH_CreateHook((LPVOID)pShowCursor, (LPVOID)&Hooked_ShowCursor,
                          (LPVOID *)&g_pOrigShowCursor) == MH_OK) {
            MH_EnableHook((LPVOID)pShowCursor);
        }
    }
    if (pClipCursor) {
        if (MH_CreateHook((LPVOID)pClipCursor, (LPVOID)&Hooked_ClipCursor,
                          (LPVOID *)&g_pOrigClipCursor) == MH_OK) {
            MH_EnableHook((LPVOID)pClipCursor);
        }
    }
}




typedef unsigned char (__thiscall *PFN_Netc_SendPacket_1001da80)(
    void *thisPtr, unsigned char packetId, void *bitStream,
    int priority, int reliability, char orderingChannel);

static PFN_Netc_SendPacket_1001da80 g_pOrigNetcSendPacket = NULL;
static void *g_pNetcInstance_10148ed0 = NULL;

static unsigned char __fastcall Hook_Netc_SendPacket_1001da80(
    void *thisPtr, void *edxUnused,
    unsigned char packetId, void *bitStream,
    int priority, int reliability, char orderingChannel)
{
    (void)edxUnused;
    g_pNetcInstance_10148ed0 = thisPtr;


    if (packetId == 0x5Bu || packetId == 0x5Cu || packetId == 0x5Du) {
        ++g_ReportChannels.transgressionCount;
        return 1;
    }
    if (g_ReportChannels.suppressReports &&
        (packetId == 80u || packetId == 81u || packetId == 82u || packetId == 83u)) {
        ++g_ReportChannels.diagnosticCount;
        return 1;
    }

    if (NrthUI_OnPacketSent(packetId)) {
        return 1;
    }
    if (g_pOrigNetcSendPacket) {
        return g_pOrigNetcSendPacket(thisPtr, packetId, bitStream, priority, reliability, orderingChannel);
    }
    return 1;
}

static unsigned char __cdecl Hook_Netc_RetFalse_1001dc30(void) { return 0; }
static void __stdcall Hook_Netc_Ret4_1001dc40(void *a1) { (void)a1; }
static int  __cdecl Hook_Netc_RetZero_1001f500(void) { return 0; }
static int  __stdcall Hook_Netc_RetZero8_1001dc50(void *a1, void *a2) { (void)a1; (void)a2; return 0; }
static void __cdecl Hook_Netc_RetVoid_10001d20(void) { }

static bool PatchBytes_Live(void *addr, const uint8_t *bytes, size_t len)
{
    if (!addr || !bytes || len == 0) return false;
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    memcpy(addr, bytes, len);
    DWORD dummy = 0;
    VirtualProtect(addr, len, oldProt, &dummy);
    return true;
}

static void ArmNetc_Live_10020640(uint8_t *moduleBase, uint32_t moduleSize)
{
    if (!moduleBase || moduleSize == 0) return;


    static const char *const kNetcPatchPats[6] = {

        "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 0F 31 8B F0",

        "55 8B EC 56 6A ? E8",

        "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 15 ? ? ? ? 8D 85",

        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F9 89 7D ? 50 B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? 58 E8",

        "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 33 C9 BA ? ? ? ? 33 C0 ? ? ? ? 85 C0",

        "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 0F 31 8B C8"
    };
    const uint8_t kRet1[1] = { 0xC3 };
    for (int i = 0; i < 6; ++i) {
        uint8_t *hit = (uint8_t *)ResolvePattern_10002960(moduleBase, moduleSize, kNetcPatchPats[i]);
        if (hit) {
            PatchBytes_Live(hit, kRet1, 1);
        }
    }


    struct LiveNetcDetour { const char *pat; void *detour; void **orig; };
    static void *s_dummyOrig[7] = { NULL };
    LiveNetcDetour detours[8] = {

        { "55 8B EC 6A ? 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 31 45 ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 89 65 ? C7 45 ? ? ? ? ? 8B 4D ? ? ? 3C ? 75 ? 8B 41 ? 83 C1 ? 03 C8 8B 15 ? ? ? ? A1",
          (void *)&Hook_Netc_RetFalse_1001dc30, &s_dummyOrig[0] },

        { "55 8B EC 6A ? 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 31 45 ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 89 65 ? 8B F9 89 7D ? 50 B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? 58 E8",
          (void *)&Hook_Netc_Ret4_1001dc40, &s_dummyOrig[1] },

        { "53 8B DC 83 EC 08 83 E4 F0 83 C4 04 55 8B 6B ? 89 6C 24 ? 8B EC 6A FF 68 96 69 3D 10",
          (void *)&Hook_Netc_RetZero_1001f500, &s_dummyOrig[2] },

        { "53 8B DC 83 EC 08 83 E4 F0 83 C4 04 55 8B 6B ? 89 6C 24 ? 8B EC 6A FF 68 CC 67 3D 10",
          (void *)&Hook_Netc_RetZero_1001f500, &s_dummyOrig[3] },

        { "55 8B EC 6A FF 68 1C BF 3D 10",
          (void *)&Hook_Netc_RetZero_1001f500, &s_dummyOrig[4] },

        { "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 8D ? ? ? ? 50 B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? 58 E8 ? ? ? ? B9",
          (void *)&Hook_Netc_RetZero8_1001dc50, &s_dummyOrig[5] },

        { "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F9 89 BD ? ? ? ? 50 B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? 58 80 7B",
          (void *)&Hook_Netc_RetVoid_10001d20, &s_dummyOrig[6] },

        { "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F1 89 B5 ? ? ? ? 8B 7B ? 89 BD",
          (void *)&Hook_Netc_SendPacket_1001da80, (void **)&g_pOrigNetcSendPacket },
    };
    for (int i = 0; i < 8; ++i) {
        void *hit = (void *)ResolvePattern_10002960(moduleBase, moduleSize, detours[i].pat);
        if (hit) {
            if (MH_CreateHook(hit, detours[i].detour, detours[i].orig) == MH_OK) {
                MH_EnableHook(hit);
                ++g_TotalInstalledHooks;
            }
        }
    }
}

static void TryArmLoadedModules(void)
{
    static char s_clientBuf[sizeof(kCt_ClientDll)] = {0};
    static bool s_clientGate                       = false;
    static char s_netcBuf[sizeof(kCt_NetcDll)]     = {0};
    static bool s_netcGate                         = false;

    const char *clientName = NrthDecryptOnce(kCt_ClientDll, sizeof(kCt_ClientDll), 0x2D,
                                             s_clientBuf, &s_clientGate);
    const char *netcName   = NrthDecryptOnce(kCt_NetcDll, sizeof(kCt_NetcDll), 0x20,
                                             s_netcBuf, &s_netcGate);

    if (g_lClientArmed == 0) {
        HMODULE hClient = GetModuleHandleA(clientName);
        if (hClient && InterlockedCompareExchange(&g_lClientArmed, 1, 0) == 0) {
            uint32_t modSize = GetLoadedModuleSize(hClient);
            ArmClient_10005b80((uint8_t *)hClient, modSize, true);
            ResolveClientOffsets_1000c390((const uint8_t *)hClient, modSize);
        }
    }

    if (g_lNetcArmed == 0) {
        HMODULE hNetc = GetModuleHandleA(netcName);
        if (hNetc && InterlockedCompareExchange(&g_lNetcArmed, 1, 0) == 0) {
            uint32_t modSize = GetLoadedModuleSize(hNetc);
            ArmNetc_Live_10020640((uint8_t *)hNetc, modSize);
        }
    }
}

static DWORD WINAPI MainInitThread(LPVOID lpParam)
{
    (void)lpParam;


    CreateDirectoryA("C:\\NVX", NULL);
    CreateDirectoryA("C:\\NVX\\logs", NULL);
    CreateDirectoryA("C:\\NVX\\dump", NULL);


    if (!NrthConfig_Load("C:\\NVX\\loader_config.cfg")) {
        NrthConfig_Load(NULL);
    }

    if (MH_Initialize() != MH_OK) {
        return 1;
    }


    static char s_ntdllBuf[sizeof(kCt_NtdllDll)]       = {0};
    static bool s_ntdllGate                            = false;
    static char s_ldrBuf[sizeof(kCt_LdrLoadDll)]       = {0};
    static bool s_ldrGate                              = false;

    const char *ntdllName = NrthDecryptOnce(kCt_NtdllDll, sizeof(kCt_NtdllDll), 0x2D,
                                            s_ntdllBuf, &s_ntdllGate);
    const char *ldrName   = NrthDecryptOnce(kCt_LdrLoadDll, sizeof(kCt_LdrLoadDll), 0x2D,
                                            s_ldrBuf, &s_ldrGate);

    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (hNtdll) {
        FARPROC pLdrLoadDll = GetProcAddress(hNtdll, ldrName);
        if (pLdrLoadDll) {
            if (MH_CreateHook((LPVOID)pLdrLoadDll, (LPVOID)&Hooked_LdrLoadDll,
                              (LPVOID *)&g_pOrigLdrLoadDll) == MH_OK &&
                MH_EnableHook((LPVOID)pLdrLoadDll) == MH_OK) {
                ++g_TotalInstalledHooks;
            }
        }
    }


    TryArmLoadedModules();


    if (g_lOverlayArmed == 0) {
        void **vtable = GetD3D9DeviceVTable();
        if (vtable && InterlockedCompareExchange(&g_lOverlayArmed, 1, 0) == 0) {
            if (!InstallD3D9Hooks(vtable)) {
                InterlockedExchange(&g_lOverlayArmed, 0);
            } else {
                InstallCursorHooks_100165ee();
            }
        }
    }


    while (!(GetAsyncKeyState(VK_END) & 1)) {
        Sleep(50);
    }
    return 0;
}

static uint32_t GetLoadedModuleSize(HMODULE hMod)
{
    if (!hMod) return 0;
    const uint8_t *base = (const uint8_t *)hMod;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return (uint32_t)nt->OptionalHeader.SizeOfImage;
}

static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR SearchPath, PULONG DllCharacteristics,
                                        NVX_UNICODE_STRING *ModuleFileName, PVOID *DllHandle)
{
    NTSTATUS status = g_pOrigLdrLoadDll(SearchPath, DllCharacteristics, ModuleFileName, DllHandle);

    if (status >= 0 && ModuleFileName && ModuleFileName->Buffer && ModuleFileName->Length > 0) {

        char lowerName[MAX_PATH] = {0};
        USHORT nChars = ModuleFileName->Length / sizeof(WCHAR);
        if (nChars >= MAX_PATH) {
            nChars = MAX_PATH - 1;
        }
        for (USHORT i = 0; i < nChars; ++i) {
            WCHAR wc = ModuleFileName->Buffer[i];
            char c = (wc < 0x80) ? (char)wc : '?';
            if (c >= 'A' && c <= 'Z') {
                c = (char)(c + ('a' - 'A'));
            }
            lowerName[i] = c;
        }
        lowerName[nChars] = '\0';

        if (strstr(lowerName, "client.dll") != NULL || strstr(lowerName, "netc.dll") != NULL) {
            TryArmLoadedModules();
        }
    }
    return status;
}

static void **GetD3D9DeviceVTable(void)
{
    static void **pCachedVTable = NULL;
    if (pCachedVTable) {
        return pCachedVTable;
    }

    static char s_d3dBuf[sizeof(kCt_D3d9Dll)] = {0};
    static bool s_d3dGate                     = false;
    const char *d3dName = NrthDecryptOnce(kCt_D3d9Dll, sizeof(kCt_D3d9Dll), 0x2D,
                                          s_d3dBuf, &s_d3dGate);

    HMODULE hD3D = GetModuleHandleA(d3dName);
    if (!hD3D) {
        char sysDir[MAX_PATH] = {0};
        if (GetSystemDirectoryA(sysDir, MAX_PATH) > 0) {
            char fullD3D[MAX_PATH] = {0};
            snprintf(fullD3D, sizeof(fullD3D), "%s\\d3d9.dll", sysDir);
            hD3D = LoadLibraryA(fullD3D);
        }
        if (!hD3D) {
            hD3D = LoadLibraryA(d3dName);
        }
    }
    if (!hD3D) {
        return NULL;
    }




    uint32_t d3dSize = GetLoadedModuleSize(hD3D);
    if (d3dSize > 0x0Eu) {
        uint32_t scanLen = (d3dSize > 0x128000u) ? 0x128000u : d3dSize;
        void **cand = FindD3D9VTableInBuffer_10012980((const uint8_t *)hD3D, scanLen);
        if (cand &&
            Nrth_IsPointerReadable_VirtualQuery(cand) &&
            Nrth_IsPointerReadable_VirtualQuery(cand[16]) &&
            Nrth_IsPointerReadable_VirtualQuery(cand[17])) {
            pCachedVTable = cand;
            return pCachedVTable;
        }
    }
    return NULL;
}

static bool InstallD3D9Hooks(void **vtable)
{
    if (!vtable || !vtable[16] || !vtable[17]) {
        return false;
    }
    if (MH_CreateHook(vtable[17], (LPVOID)&Hooked_Present, (LPVOID *)&g_pOrigPresent) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(vtable[17]) != MH_OK) {
        MH_RemoveHook(vtable[17]);
        g_pOrigPresent = NULL;
        return false;
    }
    if (MH_CreateHook(vtable[16], (LPVOID)&Hooked_Reset, (LPVOID *)&g_pOrigReset) != MH_OK) {
        MH_DisableHook(vtable[17]);
        MH_RemoveHook(vtable[17]);
        g_pOrigPresent = NULL;
        return false;
    }
    if (MH_EnableHook(vtable[16]) != MH_OK) {
        MH_RemoveHook(vtable[16]);
        MH_DisableHook(vtable[17]);
        MH_RemoveHook(vtable[17]);
        g_pOrigReset   = NULL;
        g_pOrigPresent = NULL;
        return false;
    }
    g_TotalInstalledHooks += 2;
    return true;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void ToggleMenuState(void)
{
    ULONGLONG now = GetTickCount64();
    if (now - g_lastToggleTick < 250ULL) {
        return;
    }
    g_lastToggleTick = now;
    g_bMenuOpen = !g_bMenuOpen;

    if (g_bMenuOpen) {
        GetCursorPos(&g_savedCursorPos);
        if (g_pOrigClipCursor) g_pOrigClipCursor(NULL);
        else ClipCursor(NULL);
        if (g_pOrigShowCursor) g_pOrigShowCursor(TRUE);
        else ShowCursor(TRUE);
        ReleaseCapture();
    } else {
        if (g_pOrigSetCursorPos) {
            g_pOrigSetCursorPos(g_savedCursorPos.x, g_savedCursorPos.y);
        } else {
            SetCursorPos(g_savedCursorPos.x, g_savedCursorPos.y);
        }
    }
}


static LRESULT CALLBACK GameWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int toggleVk = g_cfg.menuKey ? g_cfg.menuKey : VK_INSERT;
    if (msg == WM_KEYDOWN && (int)wParam == toggleVk && (lParam & 0x40000000L) == 0) {
        ToggleMenuState();
        return 0;
    }

    if (g_bMenuOpen) {
        ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);


        if ((msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) || msg == WM_INPUT) {
            return 1;
        }
        if (msg == WM_SETCURSOR) {
            SetCursor(LoadCursorA(NULL, IDC_ARROW));
            return TRUE;
        }
    }

    if (g_pOrigWndProc) {
        return CallWindowProcW(g_pOrigWndProc, hWnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static BOOL CALLBACK FindOwnProcessWindowProc(HWND hwnd, LPARAM lParam)
{
    DWORD wPid = 0;
    GetWindowThreadProcessId(hwnd, &wPid);
    if (wPid == GetCurrentProcessId() && IsWindowVisible(hwnd)) {
        *(HWND *)lParam = hwnd;
        return FALSE;
    }
    return TRUE;
}

static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice, HWND hDestWindow)
{
    if (g_bOverlayInit || !pDevice) {
        return;
    }


    HWND hWnd = NULL;
    D3DDEVICE_CREATION_PARAMETERS cp;
    memset(&cp, 0, sizeof(cp));
    if (SUCCEEDED(pDevice->GetCreationParameters(&cp)) && cp.hFocusWindow && IsWindow(cp.hFocusWindow)) {
        hWnd = cp.hFocusWindow;
    }
    if (!hWnd && hDestWindow && IsWindow(hDestWindow)) {
        hWnd = hDestWindow;
    }
    if (!hWnd) {
        EnumWindows(FindOwnProcessWindowProc, (LPARAM)&hWnd);
    }
    if (!hWnd) {
        return;
    }

    g_pDevice  = pDevice;
    g_hGameWnd = hWnd;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = NULL;
    NrthUI_ApplyTheme();




    {
        static const ImWchar kEnRanges[] = { 0x0020, 0x00FF, 0 };
        static const ImWchar kArRanges[] = {
            0x0020, 0x00FF,
            0x0600, 0x06FF,
            0x0750, 0x077F,
            0x08A0, 0x08FF,
            0xFB50, 0xFDFF,
            0xFE70, 0xFEFF,
            0,
        };
        ImFontConfig fcEn;
        ImFontConfig fcAr;
        fcEn.FontDataOwnedByAtlas = false;
        fcAr.FontDataOwnedByAtlas = false;
        fcEn.OversampleH = 2; fcEn.OversampleV = 1;
        fcAr.OversampleH = 2; fcAr.OversampleV = 1;
        ImFont *pFontEn = io.Fonts->AddFontFromMemoryTTF(
            (void *)kFontEnglishTTF, (int)sizeof(kFontEnglishTTF), 17.0f, &fcEn, kEnRanges);
        ImFont *pFontAr = io.Fonts->AddFontFromMemoryTTF(
            (void *)kFontArabicTTF, (int)sizeof(kFontArabicTTF), 17.0f, &fcAr, kArRanges);
        NrthUI_SetFonts(pFontEn, pFontAr);
        io.FontDefault = pFontEn ? pFontEn : io.Fonts->Fonts[0];
    }

    if (!ImGui_ImplWin32_Init(g_hGameWnd)) {
        return;
    }
    if (!ImGui_ImplDX9_Init(pDevice)) {
        ImGui_ImplWin32_Shutdown();
        return;
    }


    g_pOrigWndProc = (WNDPROC)SetWindowLongW(g_hGameWnd, GWL_WNDPROC, (LONG)GameWndProc);

    g_bOverlayInit = true;
}

static void BuildOverlayMenu(void)
{
    NrthUI_Build();
}

static void UpdateOverlayInput(void)
{
    ImGuiIO &io = ImGui::GetIO();

    if (!g_bMenuOpen) {
        io.MouseDrawCursor = false;
        return;
    }

    io.MouseDrawCursor = true;

    POINT pt;
    if (GetCursorPos(&pt) && g_hGameWnd) {
        ScreenToClient(g_hGameWnd, &pt);
        io.MousePos = ImVec2((float)pt.x, (float)pt.y);
    }

    io.MouseDown[0] = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    io.MouseDown[1] = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
    io.MouseDown[2] = (GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0;
}

static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *pDevice, const RECT *pSrc,
                                     const RECT *pDest, HWND hDestWindow, const RGNDATA *pDirty)
{
    if (!pDevice) {
        return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
    }


    HRESULT coop = pDevice->TestCooperativeLevel();
    if (coop == D3DERR_DEVICELOST) {
        return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
    }
    if (coop == D3DERR_DEVICENOTRESET) {
        if (g_bOverlayInit) {
            ImGui_ImplDX9_InvalidateDeviceObjects();
        }
        return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
    }

    EnsureOverlayInitialized(pDevice, hDestWindow);

    if (g_bOverlayInit) {
        int toggleVk = g_cfg.menuKey ? g_cfg.menuKey : VK_INSERT;
        if (GetAsyncKeyState(toggleVk) & 1) {
            ToggleMenuState();
        }

        UpdateOverlayInput();


        Nrth_TickGameFeatures_10015812();

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        NrthUI_RenderFrame(g_bMenuOpen);

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    }

    return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
}

static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *pDevice, D3DPRESENT_PARAMETERS *pParams)
{
    if (g_bOverlayInit) {
        ImGui_ImplDX9_InvalidateDeviceObjects();
    }
    HRESULT hr = g_pOrigReset(pDevice, pParams);
    if (SUCCEEDED(hr) && g_bOverlayInit) {
        ImGui_ImplDX9_CreateDeviceObjects();
    }
    return hr;
}

static const char *BaseNameA(const char *path)
{
    const char *slash = strrchr(path, '\\');
    return slash ? slash + 1 : path;
}

#endif
