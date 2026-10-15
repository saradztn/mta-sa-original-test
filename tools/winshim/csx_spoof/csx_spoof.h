/* Minimal stub for the csx_spoof interface - syntax checking only.
 * NOTE: the real csx_spoof/csx_spoof.h is NOT in this repository, so the
 * Windows build cannot succeed from these sources alone (see tools notes). */
#ifndef NRTH_WINSHIM_CSX_SPOOF_H
#define NRTH_WINSHIM_CSX_SPOOF_H
#ifdef __cplusplus
extern "C" {
#endif
#define CSX_S 0
int      CsxSpoofer_Init(void);
void     CsxSpoofer_Shutdown(void);
int      CsxSpoofer_IsEnabled(void);
int      CSX_SpooferResetMtaSerial(const char *);
const char *CSX_SpooferLastStatus(void);
#ifdef __cplusplus
}
#endif
#endif
