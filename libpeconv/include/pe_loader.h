#pragma once

#include "pe_raw_to_virtual.h"

/**
Reads PE from the given file into memory and maps it into vitual format.
(Automatic raw to virtual conversion).
If the executable flag is true, the PE file is loaded into executable memory.
If the relocate flag is true, applies relocations. Does not load imports.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
*/
BYTE* load_pe_module(char *filename, OUT size_t &v_size, bool executable, bool relocate);

/**
Loads full PE in a way in which it can be directly executed: remaps to virual format, applies relocations, loads imports.
*/
LPVOID load_pe_executable(char *filename, OUT size_t &v_size);
