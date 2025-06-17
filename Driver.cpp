#include "driver.h"
uintptr_t GIOPhysicalDriver::MapPhysicalMemory(uintptr_t physical_address, unsigned long size)
{
	PhysicalMemoryMapping in_buffer = { 0, 0, physical_address, 0, size };
	uintptr_t out_buffer[2] = { 0 };
	unsigned long returned = 0;
	DeviceIoControl(this->driverHandle, IOCTL_MAP_PHYSICAL_MEMORY, reinterpret_cast<LPVOID>(&in_buffer), sizeof(in_buffer),
		reinterpret_cast<LPVOID>(out_buffer), sizeof(out_buffer), &returned, NULL);
	return out_buffer[0];
}

uintptr_t GIOPhysicalDriver::UnmapPhysicalMemory(uintptr_t address)
{
	uintptr_t in_buffer = address;
	uintptr_t out_buffer[2] = { 0 };
	unsigned long returned = 0;
	DeviceIoControl(this->driverHandle, IOCTL_UNMAP_PHYSICAL_MEMORY, reinterpret_cast<LPVOID>(&in_buffer), sizeof(in_buffer),
		reinterpret_cast<LPVOID>(out_buffer), sizeof(out_buffer), &returned, NULL);

	return out_buffer[0];
}

uintptr_t GIOPhysicalDriver::GetSystemCR3()
{
	for (int i = 0; i < 10; i++)
	{
		uintptr_t lpBuffer = this->MapPhysicalMemory(i * 0x10000, 0x10000);

		for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
		{

			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0))
				continue;

			return *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0);
		}

		this->UnmapPhysicalMemory(lpBuffer);
	}

	return NULL;
}

bool GIOPhysicalDriver::ReadPhysicalMemory(uintptr_t physical_address, void* output, unsigned long size)
{
	uintptr_t virtual_address = this->MapPhysicalMemory(physical_address, size);
	if (!virtual_address)
		return false;
	memcpy(output, reinterpret_cast<LPCVOID>(virtual_address), size);
	this->UnmapPhysicalMemory(virtual_address);
	return true;
}

uintptr_t GIOPhysicalDriver::VirtualToPhysical(uintptr_t virtual_address)
{
	uintptr_t va = virtual_address;

	unsigned short PML4 = (unsigned short)((va >> 39) & 0x1FF);
	uintptr_t PML4E = 0;
	this->ReadPhysicalMemory((this->systemCR3 + PML4 * sizeof(uintptr_t)), &PML4E, sizeof(PML4E));

	unsigned short DirectoryPtr = (unsigned short)((va >> 30) & 0x1FF);
	uintptr_t PDPTE = 0;
	this->ReadPhysicalMemory(((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), &PDPTE, sizeof(PDPTE));

	if ((PDPTE & (1 << 7)) != 0)
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);

	unsigned short Directory = (unsigned short)((va >> 21) & 0x1FF);

	uintptr_t PDE = 0;
	this->ReadPhysicalMemory(((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), &PDE, sizeof(PDE));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	unsigned short Table = (unsigned short)((va >> 12) & 0x1FF);
	uintptr_t PTE = 0;
	this->ReadPhysicalMemory(((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), &PTE, sizeof(PTE));
	if (PTE == 0)
		return 0;
	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}

bool GIOPhysicalDriver::ReadVirtualMemory(uintptr_t address, LPVOID output, unsigned long size)
{
	if (!address || !size)
		return false;
	uintptr_t physical_address = this->VirtualToPhysical(address);
	if (!physical_address)
		return false;
	this->ReadPhysicalMemory(physical_address, output, size);
	return true;
}
