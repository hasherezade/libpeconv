/**
* @file
* @brief   Functions related to manual retrieving of PE resources.
*/

#pragma once

#include <windows.h>
#include "buffer_util.h"

namespace peconv {

    const LPSTR RT_RCDATA_A = MAKEINTRESOURCEA(10);

    /**
    Maps a resource with the given id + type and copies its raw content into the output buffer. 
    If out_size is not zero, it reads maximum out_size of bytes. If out_size is zero, it reads the full resource.
    The actual read size is returned back in out_size.
    Automatically allocates a buffer of the required size.
    If hInstance is NULL, it search the resource in the current module. Otherwise, it search in the given module.
    */
    peconv::ALIGNED_BUF load_resource_data(OUT size_t &out_size, const int res_id, const LPSTR res_type = RT_RCDATA_A, HMODULE hInstance = nullptr);

    /**
    Free the buffer with PE Resources, mapped by the function load_resource_data.
    */
    void free_resource_data(peconv::ALIGNED_BUF buffer);

    /**
    a helper function to get the module handle of the current DLL
    */
    HMODULE get_current_module_handle();

}; //namespace peconv
