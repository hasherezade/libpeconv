/**
* @file
* @brief   Functions related to finding caves in the loaded PE file.
*/

#pragma once

#include <windows.h>

namespace peconv {

    /**
    Finds cave at the end of the image
    \param module_ptr : the module where the cave should be searched
    \param module_size : the size of the module
    \param cave_size : required minimal size of the available cave
    \param req_charact : required characteristics of the cave
    \param reserve : if true: modify the header of the section containing the cave to include the cave into its size
    \return pointer to the start of the cave
    */
    PBYTE find_ending_cave(BYTE* module_ptr, size_t module_size, const DWORD cave_size, const DWORD req_charact =IMAGE_SCN_MEM_READ, bool reserve=true);

    /**
    Finds cave in the difference between the original raw size, and the raw size rounded to the aligmnent
    \param module_ptr : the module where the cave should be searched
    \param module_size : the size of the module
    \param cave_size : required minimal size of the available cave
    \param req_charact : required characteristics of the cave
    \param reserve : if true: modify the header of the section containing the cave to include the cave into its size
    \return pointer to the start of the cave
    */
    PBYTE find_alignment_cave(BYTE* module_ptr, size_t module_size, const DWORD cave_size, const DWORD req_charact = IMAGE_SCN_MEM_READ, bool reserve = true);

    /**
    Finds cave at the end of the section, that comes from a NULL padding or INT3 padding
    */
    PBYTE find_padding_cave(BYTE* module_ptr, size_t module_size, const size_t minimal_size, const DWORD req_charact = IMAGE_SCN_MEM_READ);

};//namespace peconv
