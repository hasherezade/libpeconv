#pragma once

#include <Windows.h>

namespace peconv {

    /*
    find_ending_cave: finds cave at the end of the image (extend last section's raw size without extending full image size)
    */
    PBYTE find_ending_cave(BYTE* module_ptr, size_t module_size, DWORD cave_size, DWORD cave_charact=IMAGE_SCN_MEM_READ);

    PBYTE find_section_cave(BYTE* modulePtr, size_t moduleSize, DWORD cave_size, DWORD req_charact = IMAGE_SCN_MEM_READ);

};//namespace peconv
