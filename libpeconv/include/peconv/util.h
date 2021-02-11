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

    /**
    Verifies that the calling process has a defined access to the specified range of memory.
    \param areaStart : A pointer to the first byte of the memory block
    \param areaSize : The size of the memory block, in bytes. If this parameter is zero, the return value is false.
    */
    bool is_mem_accessible(LPCVOID areaStart, SIZE_T areaSize, DWORD accessRights);

    /**
    Verifies that the calling process has read access to the specified range of memory.
    \param areaStart : A pointer to the first byte of the memory block
    \param areaSize : The size of the memory block, in bytes. If this parameter is zero, the return value is true (bad pointer).
    */
    bool is_bad_read_ptr(LPCVOID areaStart, SIZE_T areaSize);
};

