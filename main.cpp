#include "driver.h"
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <fstream>
#pragma comment(lib, "ntdll.lib")
typedef struct _SYSTEM_MODULE_ENTRY {
    PVOID  Reserved1;
    PVOID  Reserved2;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ModuleCount;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
inline NTSTATUS NtQuerySystemInformation_Dynamic(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    static auto fn = reinterpret_cast<NTSTATUS(WINAPI*)(int, PVOID, ULONG, PULONG)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
    if (!fn) return 0;
    return fn(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}


bool FixDumpedDriver(const std::string& dumpedPath, uintptr_t imageBase) {
    HANDLE hFile = CreateFileA(dumpedPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open dumped file: %s\n", dumpedPath.c_str());
        getchar();
        exit(-1);
    }
    DWORD fileSize = GetFileSize(hFile, nullptr);
    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READWRITE, 0, fileSize, nullptr);
    if (!hMapping) {
        printf("[!] Failed to create file mapping\n");
        getchar();
        CloseHandle(hFile);
        exit(-1);
    }

    BYTE* fileData = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!fileData) {
        printf("[!] Failed to map view of file\n");
        getchar();
        CloseHandle(hMapping);
        CloseHandle(hFile);
        exit(-1);
    }

    auto dosHeader = (PIMAGE_DOS_HEADER)fileData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        getchar();
        if (fileData) UnmapViewOfFile(fileData);
        if (hMapping) CloseHandle(hMapping);
        if (hFile) CloseHandle(hFile);
        exit(-1);
    }

    auto ntHeader = (PIMAGE_NT_HEADERS)(fileData + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature\n");
        getchar();
        if (fileData) UnmapViewOfFile(fileData);
        if (hMapping) CloseHandle(hMapping);
        if (hFile) CloseHandle(hFile);
        exit(-1);
    }

    printf("[~] Fixing section data...\n");
    auto section = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
        section->PointerToRawData = section->VirtualAddress;
        section->SizeOfRawData = section->Misc.VirtualSize;
    }

    printf("[~] Verifying import table...\n");
    auto& importDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        printf("[!] No import table found\n");
    }
    else {
        printf("[+] Import table exists at RVA: 0x%X\n", importDir.VirtualAddress);
    }
    FlushViewOfFile(fileData, 0);
    printf("[+] Driver sections repaired successfully!\n");
    UnmapViewOfFile(fileData);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return true;
}


bool DumpDriverFromMemory(const std::string& DriverName, LPVOID base, DWORD size) {
    std::string justName = DriverName.substr(DriverName.find_last_of("\\/") + 1);
    std::string FinalPath = justName.substr(0, justName.find_last_of('.')) + "_dumped.sys";
    std::cout << "[+] Dumping driver: " << justName << "\n";
    std::cout << "[+] Saving to path: " << FinalPath << "\n";
    HANDLE hFile = CreateFileA(FinalPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create output file : %s\n", FinalPath);
        getchar();
        exit(-1);
    }
    const DWORD CHUNK_SIZE = 0x1000;
    BYTE buffer[CHUNK_SIZE];
    DWORD totalWritten = 0;
    for (DWORD offset = 0; offset < size; offset += CHUNK_SIZE) {
        DWORD currentChunk = (offset + CHUNK_SIZE > size) ? (size - offset) : CHUNK_SIZE;
        memset(buffer, 0, currentChunk);
        if (!Driver->ReadVirtualMemory((uintptr_t)base + offset, buffer, currentChunk)) {
            printf("[-] Failed to read memory at 0x%llX\n", (uintptr_t)base + offset);
            CloseHandle(hFile);
            exit(-1);
        }
        DWORD written = 0;
        if (!WriteFile(hFile, buffer, currentChunk, &written, nullptr) || written != currentChunk) {
            printf("[-] Failed to write to file at offset 0x%X\n", offset);
            CloseHandle(hFile);
            exit(-1);
        }
        totalWritten += written;
    }

    CloseHandle(hFile);
    FixDumpedDriver(FinalPath,(uintptr_t)base);
    printf("[+] Successfully dumped %lu bytes to %s\n", totalWritten, FinalPath.c_str());
    printf("[+] Press Enter To Exit");
    getchar();
    return true;
}

int main()
{
    if (Driver->Connect())
        printf("[+] Vulnerable Driver Is Loaded ...\n");
    else
    {
        printf("[-] Vulnerable Driver Is Not Loaded Pls Load it  ...\n");
        getchar();
        exit(-1);
    }
    Driver->systemCR3 = Driver->GetSystemCR3();
	if (!Driver->systemCR3)
	{
		printf("[-] Cant Get System DTB\n");
        getchar();
		exit(-1);
	}
    printf("System DTB -> %llx\n", Driver->systemCR3);
    ULONG len = 0;
    NtQuerySystemInformation_Dynamic(11, nullptr, 0, &len);
    auto* buffer = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(new BYTE[len]);
    if (NtQuerySystemInformation_Dynamic(11, buffer, len, &len)) {
        printf("[!] NtQuerySystemInformation failed\n");
        getchar();
        delete[] buffer;
        return 1;
    }
    std::ofstream log("DumpLog.ini", std::ios::app);
    for (ULONG i = 0; i < buffer->ModuleCount; ++i) {
        auto& mod = buffer->Modules[i];
        std::string name(mod.ImageName + mod.ModuleNameOffset);

        if (log.is_open()) {
            log << "[" << i << "] " << name
                << " | Base: 0x" << mod.ImageBase
                << " | Size: 0x" << std::hex << mod.ImageSize << std::dec << "\n";
        }

        std::cout << "[" << i << "] " << name
            << " | Base: 0x" << mod.ImageBase
            << " | Size: 0x" << std::hex << mod.ImageSize << std::dec << "\n";

        if (name.find("MangerSt.sys") != std::string::npos) {
            DumpDriverFromMemory(name, mod.ImageBase, mod.ImageSize);
        }
    }
    delete[] buffer;
    return 0;
}