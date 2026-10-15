/* Minimal Direct3D 9 shim - syntax checking only.
 * Only the surface used by this repository is declared: the D3D9 layer is
 * reached through raw vtable pointers, so the method list here exists to make
 * the calls and the typedefs compile, not to model the real interface layout. */
#ifndef NRTH_WINSHIM_D3D9_H
#define NRTH_WINSHIM_D3D9_H
#include "windows.h"

typedef DWORD D3DCOLOR;
typedef struct _D3DPRESENT_PARAMETERS_ {
    UINT  BackBufferWidth, BackBufferHeight;
    DWORD BackBufferFormat, BackBufferCount;
    DWORD MultiSampleType, MultiSampleQuality;
    DWORD SwapEffect;
    HWND  hDeviceWindow;
    BOOL  Windowed;
    BOOL  EnableAutoDepthStencil;
    DWORD AutoDepthStencilFormat;
    DWORD Flags;
    UINT  FullScreen_RefreshRateInHz;
    UINT  PresentationInterval;
} D3DPRESENT_PARAMETERS;

typedef struct _D3DDEVICE_CREATION_PARAMETERS {
    UINT  AdapterOrdinal;
    DWORD DeviceType;
    HWND  hFocusWindow;
    DWORD BehaviorFlags;
} D3DDEVICE_CREATION_PARAMETERS;

#define D3D_SDK_VERSION 32
#define D3DADAPTER_DEFAULT 0
#define D3DDEVTYPE_HAL 1
#define D3DCREATE_SOFTWARE_VERTEXPROCESSING 0x00000020
#define D3DCREATE_HARDWARE_VERTEXPROCESSING 0x00000040
#define D3DERR_DEVICELOST        ((long)0x88760868)
#define D3DERR_DEVICENOTRESET    ((long)0x88760869)
#define D3DERR_INVALIDCALL       ((long)0x8876086C)
#define D3D_OK                   ((long)0)

struct IDirect3D9;

struct IDirect3DDevice9 {
    virtual long TestCooperativeLevel(void) = 0;
    virtual long GetCreationParameters(D3DDEVICE_CREATION_PARAMETERS *) = 0;
    virtual long Present(const RECT *, const RECT *, HWND, const void *) = 0;
    virtual long Reset(D3DPRESENT_PARAMETERS *) = 0;
};

struct IDirect3D9 {
    virtual long CreateDevice(UINT, DWORD, HWND, DWORD, D3DPRESENT_PARAMETERS *, IDirect3DDevice9 **) = 0;
};

#ifdef __cplusplus
extern "C" {
#endif
void *Direct3DCreate9(unsigned int);
#ifdef __cplusplus
}
#endif
#endif
