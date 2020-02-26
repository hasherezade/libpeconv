/**
* @file
* @brief   Functions related to finding a base to which the module was relocated.
*/

#pragma once

#include <Windows.h>

namespace peconv {

    /**
    Try to find a base to which the PE file was relocated, basing on the filled relocations.
    WARNING: sometimes it may give inaccurate results.
    \param module_ptr : the module which's base is being searched
    \param module_size : the size of the given module
    \return the base to which the module was relocated
    */
    ULONGLONG find_base_candidate(IN BYTE *module_ptr, IN size_t module_size);
};
