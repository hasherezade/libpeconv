#pragma once

#include <Windows.h>
#include "buffer_util.h"

#include "load_config_defs.h"

namespace peconv {

    /**
    A version of Load Config Directory.
    */
    typedef enum {
        LOAD_CONFIG_NONE = 0,
        LOAD_CONFIG_W7_VER = 7,
        LOAD_CONFIG_W8_VER = 8,
        LOAD_CONFIG_W10_VER = 10,
        LOAD_CONFIG_UNK_VER = -1
    } t_load_config_ver;

    /**
    Get a pointer to the Load Config Directory within the given PE.
    \param buffer : a buffer containing the PE file in a Virtual format
    \param buf_size : size of the buffer
    \return a pointer to the Load Config Directory, NULL if the given PE does not have this directory
    */
    BYTE* get_load_config_ptr(BYTE* buffer, size_t buf_size);

    /**
    Detect which version of Load Config Directory was used in the given PE.
    \param buffer : a buffer containing the PE file in a Virtual format
    \param buf_size : size of the buffer
    \ld_config_ptr : pointer to the Load Config Directory within the given PE
    \return detected version of Load Config Directory
    */
    t_load_config_ver get_load_config_version(BYTE* buffer, size_t buf_size, BYTE* ld_config_ptr);

}; // namespace peconv
