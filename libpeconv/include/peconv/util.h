/**
* @file
* @brief   Miscellaneous utility functions.
*/

#pragma once

#include "file_util.h"
#include "resource_util.h"

namespace peconv {
    /**
    Checks if the given buffer is fully filled with the specified character.
    \param cave_ptr : pointer to the buffer to be checked
    \param cave_size : size of the buffer to be checked
    \param padding_char : the required character
    */
    bool is_padding(const BYTE *cave_ptr, size_t cave_size, const BYTE padding_char);

    /**
    Wrapper for GetProcessId - for a backward compatibility with old versions of Windows
    */
    DWORD get_process_id(HANDLE hProcess);
};

