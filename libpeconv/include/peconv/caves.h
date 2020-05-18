/**
* @file
* @brief   Functions related to finding caves in the loaded PE file.
*/

#pragma once

#include <windows.h>

namespace peconv {

    /**
    Finds cave at the end of the image (extend last section's raw size without extending the full image size)
    */
    PBYTE find_ending_cave(BYTE* module_ptr, size_t module_size, const DWORD cave_size, const DWORD cave_charact=IMAGE_SCN_MEM_READ);

    /**
    Finds cave in the difference between the original raw size, and the raw size rounded to the aligmnent
    */
    PBYTE find_alignment_cave(BYTE* modulePtr, size_t moduleSize, const DWORD cave_size, const DWORD req_charact = IMAGE_SCN_MEM_READ);

    /**
    Finds cave at the end of the section, that comes from a NULL padding or INT3 padding
    */
    PBYTE find_padding_cave(BYTE* modulePtr, size_t moduleSize, const size_t minimal_size, const DWORD req_charact = IMAGE_SCN_MEM_READ);

};//namespace peconv
