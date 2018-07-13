#include "peconv\cave.h"
#include "peconv\pe_hdrs_helper.h"

using namespace peconv;

#ifdef _DEBUG
#include <iostream>
#endif

PBYTE peconv::find_ending_cave(BYTE*modulePtr, size_t moduleSize, DWORD minimal_size, DWORD req_charact)
{
    size_t sec_count = peconv::get_sections_count(modulePtr, moduleSize);
    if (sec_count == 0) return nullptr;

    size_t last_sec = sec_count - 1;
    PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(modulePtr, moduleSize, last_sec);
    if (section_hdr == nullptr) return nullptr;
    if (!(section_hdr->Characteristics & req_charact)) return nullptr;

    DWORD raw_size = section_hdr->SizeOfRawData;
    DWORD virtual_size = (DWORD)moduleSize - section_hdr->VirtualAddress;

    if (raw_size >= virtual_size) {
#ifdef _DEBUG
        std::cout << "Last section's raw_size: " << std::hex << raw_size << " >= virtual_size: " << virtual_size << std::endl;
#endif
        return nullptr;
    }
    DWORD cave_size = virtual_size - raw_size;
    if (cave_size < minimal_size) {
#ifdef _DEBUG
        std::cout << "Cave is too small" << std::endl;
#endif
        return nullptr;
    }
    PBYTE cave_ptr = modulePtr + section_hdr->VirtualAddress + section_hdr->SizeOfRawData;
    if (!validate_ptr(modulePtr, moduleSize, cave_ptr, minimal_size)) {
#ifdef _DEBUG
        std::cout << "Invalid cave pointer" << std::endl;
#endif
        return nullptr;
    }
    section_hdr->SizeOfRawData += minimal_size; //book this cave
    return cave_ptr;
}
