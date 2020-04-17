#include "peconv/caves.h"
#include "peconv/pe_hdrs_helper.h"
#include "peconv/util.h"

using namespace peconv;

#ifdef _DEBUG
#include <iostream>
#endif

PBYTE peconv::find_ending_cave(BYTE*modulePtr, size_t moduleSize, const DWORD minimal_size, const DWORD req_charact)
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

PBYTE peconv::find_alignment_cave(BYTE* modulePtr, size_t moduleSize, const DWORD minimal_size, const DWORD req_charact)
{
    DWORD alignment = peconv::get_sec_alignment(modulePtr, true);
    if (alignment == 0) return nullptr;

    size_t sec_count = peconv::get_sections_count(modulePtr, moduleSize);
    for (size_t i = 0; i < sec_count; i++) {
        PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(modulePtr, moduleSize, i);
        if (section_hdr == nullptr) continue;
        if (!(section_hdr->Characteristics & req_charact)) continue;

        DWORD rem = section_hdr->SizeOfRawData % alignment;
        if (rem == 0) continue;

        DWORD div = (section_hdr->SizeOfRawData / alignment) + 1;
        DWORD new_size = div * alignment;
        DWORD cave_size = new_size - section_hdr->SizeOfRawData;
        if (cave_size < minimal_size) {
#ifdef __DEBUG
            std::cout << "Cave is too small" << std::endl;
#endif
            continue;
        }
        DWORD sec_start = section_hdr->PointerToRawData;
        if (sec_start == 0) continue;

        DWORD sec_end = sec_start + section_hdr->SizeOfRawData;
#ifdef _DEBUG
        std::cout << "section: " << std::hex << sec_start << " : " << sec_end << std::endl;
#endif
        PBYTE cave_ptr = modulePtr + sec_end;
        if (!validate_ptr(modulePtr, moduleSize, cave_ptr, minimal_size)) {
#ifdef _DEBUG
            std::cout << "Invalid cave pointer" << std::endl;
#endif
            continue;
        }
        section_hdr->SizeOfRawData += minimal_size; //book this cave
        return cave_ptr;
    }
#ifdef _DEBUG
    std::cout << "Cave not found" << std::endl;
#endif
    return nullptr;
}

PBYTE peconv::find_padding_cave(BYTE* modulePtr, size_t moduleSize, const size_t minimal_size, const DWORD req_charact)
{
    size_t sec_count = peconv::get_sections_count(modulePtr, moduleSize);
    for (size_t i = 0; i < sec_count; i++) {
        PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(modulePtr, moduleSize, i);
        if (section_hdr == nullptr) continue;
        if (!(section_hdr->Characteristics & req_charact)) continue;

        if (section_hdr->SizeOfRawData < minimal_size) continue;

        // we will be searching in the loaded, virtual image:
        DWORD sec_start = section_hdr->VirtualAddress;
        if (sec_start == 0) continue;

        DWORD sec_end = sec_start + section_hdr->SizeOfRawData;
#ifdef _DEBUG
        std::cout << "section: " << std::hex << sec_start << " : " << sec_end << std::endl;
#endif
        //offset from the end of the section:
        size_t cave_offset = section_hdr->SizeOfRawData - minimal_size;
        PBYTE cave_ptr = modulePtr + sec_start + cave_offset;
        if (!validate_ptr(modulePtr, moduleSize, cave_ptr, minimal_size)) {
#ifdef _DEBUG
            std::cout << "Invalid cave pointer" << std::endl;
#endif
            continue;
        }
        bool found = false;
        if (is_padding(cave_ptr, minimal_size, 0)) {
            found = true;
        }
        //if the section is code, check also code padding:
        if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (is_padding(cave_ptr, minimal_size, 0xCC)) {
                found = true;
            }
        }
        if (found) {
            return cave_ptr;
        }
    }
#ifdef _DEBUG
    std::cout << "Cave not found" << std::endl;
#endif
    return nullptr;
}
