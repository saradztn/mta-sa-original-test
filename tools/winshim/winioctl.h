/* Win32 ioctl shim - syntax checking only. */
#ifndef NRTH_WINSHIM_WINIOCTL_H
#define NRTH_WINSHIM_WINIOCTL_H
#include "windows.h"
typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty = 1
} STORAGE_PROPERTY_ID;

typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,
    PropertyExistsQuery = 1
} STORAGE_QUERY_TYPE;

typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE  QueryType;
    BYTE AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef struct _STORAGE_DESCRIPTOR_HEADER {
    DWORD Version;
    DWORD Size;
} STORAGE_DESCRIPTOR_HEADER, *PSTORAGE_DESCRIPTOR_HEADER;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    DWORD Version;
    DWORD Size;
    BYTE  DeviceType;
    BYTE  DeviceTypeModifier;
    BOOL  RemovableMedia;
    BOOL  CommandQueueing;
    DWORD VendorIdOffset;
    DWORD ProductIdOffset;
    DWORD ProductRevisionOffset;
    DWORD SerialNumberOffset;
    DWORD BusType;
    DWORD RawPropertiesLength;
    BYTE  RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400

#ifdef __cplusplus
extern "C" {
#endif
WINBASEAPI BOOL WINAPI DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, DWORD *, LPVOID);
#ifdef __cplusplus
}
#endif
#endif
