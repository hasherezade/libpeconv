#pragma once
#include <Windows.h>

namespace peconv {
    // a callback
    typedef bool(*t_on_res_entry_found) (
        BYTE* modulePtr,
        IMAGE_RESOURCE_DIRECTORY_ENTRY *root_dir,
        IMAGE_RESOURCE_DATA_ENTRY *curr_entry
        );

    bool parse_resources(BYTE* modulePtr, t_on_res_entry_found on_entry);
};
