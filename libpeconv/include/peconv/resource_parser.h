/**
* @file
* @brief   Parsing PE's resource directory.
*/

#pragma once
#include <windows.h>

namespace peconv {
    /**
    A callback that will be executed by the function parse_resources when the Resource Entry was found.
    */
    typedef bool(*t_on_res_entry_found) (
        BYTE* modulePtr,
        const size_t modulSize,
        IMAGE_RESOURCE_DIRECTORY_ENTRY *root_dir,
        IMAGE_RESOURCE_DATA_ENTRY *curr_entry
        );

    /**
    A function walking through the Resource Tree of the given PE. On each Resource Entry found, the callback is executed.
    \param moduleBuf : pointer to the buffer with the PE in a Virtual format
    \param modulSize : a size of the buffer pointed by moduleBuf
    \param on_entry : a callback function executed on each Resource Entry
    */
    bool parse_resources(BYTE* moduleBuf, const size_t modulSize, t_on_res_entry_found on_entry);
};
