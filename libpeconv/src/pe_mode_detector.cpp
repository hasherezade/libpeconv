#include "peconv/pe_mode_detector.h"
#include "peconv/util.h"

//TODO: fix it - it gives wrong results in some cases, i.e. UPX
bool peconv::is_pe_raw(const BYTE* pe_buffer, size_t pe_size)
{
    const size_t v_align = peconv::get_sec_alignment((PBYTE)pe_buffer, false);

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
        if (!is_padding(sec_raw_ptr, diff, 0)) {
            //this is not padding: non-zero content detected
            return true;
        }
    }
    return false;
}

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
