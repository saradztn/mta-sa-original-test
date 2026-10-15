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












#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NRTH_VK_INSERT
#define NRTH_VK_INSERT 45
#endif

typedef struct _NrthConfig {
    int  menuKey;
    int  noSpoofer;
    bool watermark;
    bool notifications;
    char activePath[260];
} NrthConfig;

extern NrthConfig g_cfg;


const char *NrthConfig_GetPrimaryPath(void);


const char *NrthConfig_GetMenuKeyFmt(void);


const char *NrthConfig_GetNoSpooferFmt(void);



bool NrthConfig_Load(const char *overridePath);




bool NrthConfig_Save(const char *overridePath);


bool NrthConfig_ParseBuffer(const char *buf, NrthConfig *cfg);


int NrthConfig_FormatBuffer(const NrthConfig *cfg, char *outBuf, uint32_t outCap);


bool NrthConfig_SaveOvr(const char *ovrPath, const char *overrideCfgPath);

#ifdef __cplusplus
}
#endif
