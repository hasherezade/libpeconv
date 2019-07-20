/**
* @file
* @brief   Operating on PE file's relocations table.
*/

#pragma once

#include <Windows.h>

namespace peconv {

    /** 
     Applies relocations on the PE in virtual format. Relocates it from the old base given to the new base given.
     If NULL was supplied as the old base, it assumes that the old base is the ImageBase given in the header.
    */
    bool relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase=NULL);

    /**
    Checks if the given  PE has a valid relocations table.
    */
    bool has_valid_relocation_table(const PBYTE modulePtr, size_t moduleSize);

};//namespace peconv
