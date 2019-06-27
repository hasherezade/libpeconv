#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"

namespace peconv {

    /**
    check if the PE in the memory is in raw format
    */
    bool is_pe_raw(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
    check if the Virtual Section alignment is identical as the Raw alignment (i.e. if the PE was realigned)
    */
    bool is_pe_raw_eq_virtual(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
    checks if the PE has sections that were unpacked/expanded in the memory
    */
    bool is_pe_expanded(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
    checks if the given section was unpacked in the memory
    */
    bool is_section_expanded(IN const BYTE* pe_buffer,
        IN size_t pe_size,
        IN const PIMAGE_SECTION_HEADER sec
    );

};// namespace peconv
