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
        IMAGE_RESOURCE_DIRECTORY_ENTRY *root_dir,
        IMAGE_RESOURCE_DATA_ENTRY *curr_entry
        );

    /**
    A function walking through the Resource Tree of the given PE. On each Resource Entry found, the callback is executed.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format
    \param on_entry : a callback function executed on each Resource Entry
    */
    bool parse_resources(BYTE* modulePtr, t_on_res_entry_found on_entry);
};
