#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")
#define IOCTL_MAP_PHYSICAL_MEMORY    0xC3502004
#define IOCTL_UNMAP_PHYSICAL_MEMORY  0xC3502008
#pragma pack(push, 1)
typedef struct _PhysicalMemoryMapping
{
    DWORD       Type;            
    DWORD       BusNumber;       
    uintptr_t   PhysicalAddress; 
    DWORD       IoSpace;         
    DWORD       Size;            
} PhysicalMemoryMapping;
#pragma pack(pop)

class GIOPhysicalDriver {
private:
    HANDLE driverHandle = NULL;

public:
    uintptr_t systemCR3 = 0;
    bool Connect() {
        driverHandle = CreateFileA("\\\\.\\GIO", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return (driverHandle != INVALID_HANDLE_VALUE);
    }
    uintptr_t GetSystemCR3();
    uintptr_t MapPhysicalMemory(uintptr_t physicalAddress, DWORD size);
    uintptr_t UnmapPhysicalMemory(uintptr_t mappedAddress);
    bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, DWORD size);
    bool ReadVirtualMemory(uintptr_t virtualAddress, void* buffer, DWORD size);
    uintptr_t VirtualToPhysical(uintptr_t virtualAddress);
};
static GIOPhysicalDriver* Driver = new GIOPhysicalDriver();
