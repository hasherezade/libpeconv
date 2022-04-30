/**
* @file
* @brief   Loading PE from a file with the help of the custom loader.
*/

#pragma once

#include "pe_raw_to_virtual.h"
#include "function_resolver.h"

namespace peconv {
    /**
    Reads PE from the given buffer into memory and maps it into virtual format.
    (Automatic raw to virtual conversion).
    If the executable flag is true, the PE file is loaded into executable memory.
    If the relocate flag is true, applies relocations. Does not load imports.
    Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_buffer.
    */
    BYTE* load_pe_module(BYTE* payload_raw, size_t r_size, OUT size_t &v_size, bool executable, bool relocate);

    /**
    Reads PE from the given file into memory and maps it into vitual format.
    (Automatic raw to virtual conversion).
    If the executable flag is true, the PE file is loaded into executable memory.
    If the relocate flag is true, applies relocations. Does not load imports.
    Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_buffer.
    */
    BYTE* load_pe_module(LPCTSTR filename, OUT size_t &v_size, bool executable, bool relocate);

    /**
    Loads full PE from the raw buffer in a way in which it can be directly executed: remaps to virual format, applies relocations, loads imports.
    Allows for supplying custom function resolver.
    */
    BYTE* load_pe_executable(BYTE* payload_raw, size_t r_size, OUT size_t &v_size, t_function_resolver* import_resolver=NULL);

    /**
    Loads full PE from file in a way in which it can be directly executed: remaps to virtual format, applies relocations, loads imports.
    Allows for supplying custom function resolver.
    */
    BYTE* load_pe_executable(LPCTSTR filename, OUT size_t &v_size, t_function_resolver* import_resolver=NULL);

};// namespace peconv
