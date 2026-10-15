/* ============================================================================
 *  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
 *  Security & Vulnerability Research Team — White Hat Hackers
 * ----------------------------------------------------------------------------
 *  MTA:SA security research test bed — mta-sa-original-test
 *  Internal security research material. All rights reserved by the team above.
 *  Redistribution, public release and reuse outside the team are not authorized.
 *  NRTH-SEC-RESEARCH-HEADER
 * ============================================================================ */
#pragma once








#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <stdint.h>
#include <stddef.h>
typedef int32_t  LRESULT;
typedef uintptr_t WPARAM;
typedef intptr_t LPARAM;
#define CALLBACK
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


#define NRTH_CLIENT_HOOK_COUNT      11
#define NRTH_NETC_SCAN_COUNT         6
#define NRTH_NETC_HOOK_COUNT         4
#define NRTH_NETC_PATCH_COUNT        6
#define NRTH_CLIENT_RESOLVE_COUNT   20
#define NRTH_TOTAL_HOOK_COUNT       18
#define NRTH_TOTAL_SCAN_COUNT       37
#define NRTH_VM_REGISTRY_CAP        32


typedef struct _NrthPatchRecord {
    uint32_t prepVa;
    uint32_t callVa;
    uint32_t patternGlobal;
    void    *targetAddr;
    uint8_t  origByte;
    uint8_t  patchByte;
    uint8_t  applied;
    uint8_t  reserved;
} NrthPatchRecord;


typedef struct _NrthHookSlot {
    uint32_t    index;
    uint32_t    handlerVa;
    uint32_t    patternSiteVa;
    uint8_t     xorKey;
    const char *pattern;
    void       *detourFn;
    void       *targetAddr;
    void       *origTrampoline;
    bool        installed;
} NrthHookSlot;


#pragma pack(push, 1)
typedef struct _NrthLuaVmSlot {
    uint8_t  resourceMeta[0x18];
    uint32_t luaStatePtr32;
} NrthLuaVmSlot;
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(NrthLuaVmSlot) == 0x1C, "VM slot stride must be 0x1C (28 bytes)");
static_assert(offsetof(NrthLuaVmSlot, luaStatePtr32) == 0x18, "lua_State* must sit at +0x18");
#endif

typedef int (*PFN_NrthLuaLoadBuffer)(void *L, const char *buff, size_t sz, const char *name);
typedef int (*PFN_NrthLuaPcall)(void *L, int nargs, int nresults, int errfunc);

typedef struct _NrthLuaVmBridge {
    NrthLuaVmSlot         registry_1013bf04[NRTH_VM_REGISTRY_CAP];
    uint32_t              slotCount;
    void                 *default_L_1013c95c;
    PFN_NrthLuaLoadBuffer loadbuffer_1013c94c;
    PFN_NrthLuaPcall      pcall_1013c974;
    uint8_t               execFlag_1013c939;
    char                  scriptBuf_1013beec[65536];
} NrthLuaVmBridge;


typedef struct _SPlayerHealthSync {
    float    fHealth;
    float    fArmor;
    uint8_t  bGodMode;
    uint8_t  bInfiniteAmmo;
    uint8_t  bAntiSpread;
    uint8_t  bHighJump;
    float    fAirBreakSpeed;
    float    fAirBreakIncr;
    uint8_t  bAirBreak;
    uint8_t  bJetpack;
    uint8_t  bGiveHp;
    uint8_t  bGiveArmor;
    uint8_t  bVehGodMode;
    uint8_t  bFallBike;
    uint8_t  bFastStop;
    uint8_t  bFlyingCar;
    uint8_t  bDriveWater;
    uint8_t  bVehicleChaos;
    uint8_t  bUnlockCar;
    uint8_t  bRepairCar;
    uint8_t  bStartEngine;
    uint8_t  bCrasher;
} SPlayerHealthSync;

typedef struct _SWeaponAimSync {
    float    fAimX;
    float    fAimY;
    float    fAimZ;
    float    fClickWarpMaxDist;
    float    fCrosshairSize;
    uint8_t  bClickWarp;
    uint8_t  bGroundWarp;
    uint8_t  bEnterVehicle;
    uint8_t  bAllWeapons;
} SWeaponAimSync;


typedef struct _NrthReportChannelState {
    uint32_t screenshotCount;
    uint32_t transgressionCount;
    uint32_t diagnosticCount;
    uint32_t acinfoCount;
    uint32_t challengeMemCount;
    bool     suppressReports;
} NrthReportChannelState;


LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam);


const uint8_t *ResolvePattern_10002960(const uint8_t *base, uint32_t size, const char *pattern);
void **FindD3D9VTableInBuffer_10012980(const uint8_t *base, uint32_t size);
bool PatchByte_10011870(void *targetAddr, uint8_t opcodeByte, uint32_t prepVa,
                        uint32_t callVa, uint32_t patternGlobal);

uint32_t ArmClient_10005b80(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours);
uint32_t ResolveClientOffsets_1000c390(const uint8_t *moduleBase, uint32_t moduleSize);
uint32_t ArmNetc_10020640(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours, bool applyPatches);


const NrthHookSlot    *Nrth_GetClientHookTable(uint32_t *outCount);
const NrthHookSlot    *Nrth_GetNetcHookTable(uint32_t *outCount);
const NrthPatchRecord *Nrth_GetPatchList_101493e4(uint32_t *outCount);
const uintptr_t       *Nrth_GetClientResolvedOffsets(uint32_t *outCount);
uint32_t               Nrth_GetTotalPatternScans(void);
uint32_t               Nrth_GetTotalInstalledHooks(void);
uint32_t               Nrth_GetTotalAppliedPatches(void);
void                   Nrth_ResetArmingCounters(void);

NrthLuaVmBridge        *Nrth_GetLuaVmBridge(void);
SPlayerHealthSync      *Nrth_GetPlayerHealthSync(void);
SWeaponAimSync         *Nrth_GetWeaponAimSync(void);
NrthReportChannelState *Nrth_GetReportChannelState(void);
bool                    Nrth_IsPointerReadable_VirtualQuery(const void *ptr);


void Nrth_AirbreakTick_10001d80(void);
void Nrth_TickGameFeatures_10015812(void);
void Nrth_TriggerAllWeapons_1002a5a7(void);
void Nrth_TriggerJetpack_1002a86c(void);
bool Nrth_RepairCurrentVehicle_1002f070(void);
bool Nrth_StartCurrentVehicleEngine_1002f0f0(void);
bool Nrth_UnlockNearestVehicle_1002eea0(void);
bool Nrth_StopCurrentVehicle(void);
bool Nrth_DestroyCurrentVehicle(void);
bool Nrth_GetLocalPlayerPosition(float *outX, float *outY, float *outZ);
bool Nrth_TeleportLocalPlayer(float x, float y, float z);
bool Nrth_StopClientResource_100054a0(const char *resName);

#ifdef __cplusplus
}
#endif
