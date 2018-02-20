#pragma once

#include <windows.h>
#include "module_helper.h"

namespace peconv {

    /**
    Maps a resource with the given id + type and copies its raw content into the output buffer. 
    If out_size is not zero, it reads maximum out_size of bytes. If out_size is zero, it reads the full resource.
    The actual read size is returned back in out_size.
    Automatically allocates a buffer of the required size.
    */
    peconv::ALIGNED_BUF load_resource_data(OUT size_t &out_size, const int res_id, const LPSTR res_type = RT_RCDATA);

    void free_resource_data(peconv::ALIGNED_BUF buffer);

}; //namespace peconv
