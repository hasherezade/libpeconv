#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"

namespace peconv {

    //check if the PE in the memory is in raw format
    bool is_pe_raw(
        _In_reads_(pe_size) const BYTE* pe_buffer,
        _In_ size_t pe_size
    );

    //checks if the PE has sections that were unpacked in the memory
    bool is_pe_expanded(
        _In_reads_(pe_size) const BYTE* pe_buffer,
        _In_ size_t pe_size
    );

    //checks if the given section was unpacked in the memory
    bool is_section_expanded(_In_reads_(pe_size) const BYTE* pe_buffer,
        _In_ size_t pe_size,
        _In_ const PIMAGE_SECTION_HEADER sec
    );

};// namespace peconv
