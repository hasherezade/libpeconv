#include "peconv/pe_mode_detector.h"
#include "peconv/util.h"
#include "peconv/imports_loader.h"

#ifdef _DEBUG
    #include <iostream>
#endif

// Check if gaps between sections are typical for Virtual Alignment.
// Returns true if confirmed, false if not confirmed. False result can also mean that data was invalid/insufficient to decide.
bool is_virtual_padding(const BYTE* pe_buffer, size_t pe_size)
{
    const size_t r_align = peconv::get_sec_alignment((PBYTE)pe_buffer, true);

    size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    if (sections_count < 2) return false;

    bool is_valid_padding = false;
    for (size_t i = 1; i < sections_count; i += 2) {
        PIMAGE_SECTION_HEADER sec1 = peconv::get_section_hdr(pe_buffer, pe_size, i-1);
        PIMAGE_SECTION_HEADER sec2 = peconv::get_section_hdr(pe_buffer, pe_size, i);

        if (sec1->SizeOfRawData == 0) continue; //skip empty sections

        const DWORD sec1_end_offset = sec1->VirtualAddress + sec1->SizeOfRawData;
        if (sec2->VirtualAddress == sec1_end_offset) continue;

        if (sec2->VirtualAddress < sec1_end_offset) {
            //std::cout << "Invalid size of the section: " << std::hex << sec2->VirtualAddress << " vs "<< sec1_end_offset << std::endl;
            return false;
        }
        const size_t diff = sec2->VirtualAddress - sec1_end_offset;
        if (diff < r_align) continue; //to small to determine

        BYTE* sec1_end_ptr = (BYTE*)((ULONGLONG)pe_buffer + sec1_end_offset);
        if (!peconv::validate_ptr((const LPVOID)pe_buffer, pe_size, sec1_end_ptr, diff)) {
            //std::cout << "Invalid pointer to the section\n";
            return false;
        }
        if (is_padding(sec1_end_ptr, diff, 0)) {
            is_valid_padding = true;
        }
        else {
            return false;
        }
    }
    return is_valid_padding;
}

// Check if the gap between the end of headers and the first section is typical for Virtual Alignment.
// Returns true if confirmed, false if not confirmed. False result can also mean that data was invalid/insufficient to decide.
bool is_hdr_virtual_align(const BYTE* pe_buffer, size_t pe_size)
{
    const size_t v_align = peconv::get_sec_alignment((PBYTE)pe_buffer, false);
    if (peconv::get_hdrs_size(pe_buffer) >= v_align) {
        //underermined for such case
        return false;
    }
    //walk through sections and check their sizes
    size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    if (sections_count == 0) return false;
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(pe_buffer, pe_size, i);
        if (sec->PointerToRawData == 0 || sec->SizeOfRawData == 0) {
            continue; // check next
        }
        if (sec->PointerToRawData >= v_align) continue;

        size_t diff = v_align - sec->PointerToRawData;
        BYTE* sec_raw_ptr = (BYTE*)((ULONGLONG)pe_buffer + sec->PointerToRawData);
        if (!peconv::validate_ptr((const LPVOID)pe_buffer, pe_size, sec_raw_ptr, diff)) {
            return false;
        }
        if (is_padding(sec_raw_ptr, diff, 0)) {
            return true;
        }
    }
    return false;
}

bool peconv::is_pe_raw(const BYTE* pe_buffer, size_t pe_size)
{
    size_t v_score = 0;
    if (peconv::has_valid_import_table((const PBYTE)pe_buffer, pe_size)) {
#ifdef _DEBUG
        std::cout << "Valid Import Table found" << std::endl;
#endif
        v_score++;
    }
    if (is_hdr_virtual_align(pe_buffer, pe_size)) {
#ifdef _DEBUG
        std::cout << "Header virtual align OK" << std::endl;
#endif
        v_score++;
    }
    if (is_virtual_padding(pe_buffer, pe_size)) {
#ifdef _DEBUG
        std::cout << "Virtual Padding OK" << std::endl;
#endif
        v_score++;
    }
#ifdef _DEBUG
    std::cout << "TOTAL v_score: " << std::dec << v_score << std::endl;
#endif
    return (v_score == 0);
}

// checks if any of the executable sections has been expanded in the memory
bool peconv::is_pe_expanded(const BYTE* pe_buffer, size_t pe_size)
{
    //walk through sections and check their sizes
    size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(pe_buffer, pe_size, i);
        //scan only executable sections
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            if (is_section_expanded(pe_buffer, pe_size, sec)) return true;
        }
    }
    return false;
}

// checks if the section's content in memory is bigger than in the raw format
bool peconv::is_section_expanded(const BYTE* pe_buffer, size_t pe_size, const PIMAGE_SECTION_HEADER sec)
{
    if (!sec) return false;

    size_t sec_vsize = peconv::get_virtual_sec_size(pe_buffer, sec, true);
    size_t sec_rsize = sec->SizeOfRawData;

    if (sec_rsize >= sec_vsize) return false;
    size_t diff = sec_vsize - sec_rsize;

    BYTE* sec_raw_end_ptr = (BYTE*)((ULONGLONG)pe_buffer + sec->VirtualAddress + sec_rsize);
    if (!peconv::validate_ptr((const LPVOID)pe_buffer, pe_size, sec_raw_end_ptr, diff)) {
        return false;
    }
    if (!is_padding(sec_raw_end_ptr, diff, 0)) {
        //this is not padding: non-zero content detected
        return true;
    }
    return false;
}
