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
#include <stddef.h>
#include <stdbool.h>

typedef struct _NrthPacketDef {
    int         id;
    const char *name;
    bool        isReportChannel;
} NrthPacketDef;

#ifdef __cplusplus
extern "C" {
#endif

void NrthUI_ApplyTheme(void);
void NrthUI_Build(void);
void NrthUI_RenderFrame(bool menuOpen);


void        NrthUI_SetLanguageArabic(bool isArabic);
bool        NrthUI_IsLanguageArabic(void);
const char *NrthUI_ShapeArabicText(const char *utf8In, char *outBuf, size_t outCap);
void        NrthUI_SetFonts(void *pEnglishFont, void *pArabicFont);



size_t NrthShape_ArabicCodepoints(const uint32_t *in, size_t n, uint32_t *out, size_t outCap);
size_t NrthBidi_ReorderVisual(const uint32_t *in, size_t n, uint32_t *out, size_t outCap);

const NrthPacketDef *NrthUI_GetPacketCatalog(uint32_t *outCount);
void                 NrthUI_SyncFeaturesToState(void);
bool                 NrthUI_ExecuteLuaViaBridge(const char *code, size_t len, int vmMode);


void     NrthUI_OnClientScriptLoaded(const char *chunkName, const char *code, size_t len);
bool     NrthUI_ShouldBlockServerEvent(const char *eventName);
void     NrthUI_OnResourceStarted(const char *resName);
bool     NrthUI_OnPacketSent(unsigned char packetId);
uint32_t NrthUI_GetMarkerCount(void);
bool     NrthUI_GetMarkerAt(uint32_t idx, float *outX, float *outY, float *outZ);
void     NrthUI_PushToastNotification(const char *msg);

#ifdef __cplusplus
}
#endif
