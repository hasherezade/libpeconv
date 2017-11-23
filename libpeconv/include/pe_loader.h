#pragma once

#include "pe_raw_to_virtual.h"

/**
Reads PE from the given buffer into memory and maps it into vitual format.
(Automatic raw to virtual conversion).
If the executable flag is true, the PE file is loaded into executable memory.
If the relocate flag is true, applies relocations. Does not load imports.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
*/
BYTE* load_pe_module(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, bool executable, bool relocate);

/**
Reads PE from the given file into memory and maps it into vitual format.
(Automatic raw to virtual conversion).
If the executable flag is true, the PE file is loaded into executable memory.
If the relocate flag is true, applies relocations. Does not load imports.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
*/
BYTE* load_pe_module(char *filename, OUT size_t &v_size, bool executable, bool relocate);

/**
Loads full PE from the raw buffer in a way in which it can be directly executed: remaps to virual format, applies relocations, loads imports.
*/
LPVOID load_pe_executable(BYTE* dllRawData, size_t r_size, OUT size_t &v_size);

/**
Loads full PE from file in a way in which it can be directly executed: remaps to virual format, applies relocations, loads imports.
*/
LPVOID load_pe_executable(char *filename, OUT size_t &v_size);
