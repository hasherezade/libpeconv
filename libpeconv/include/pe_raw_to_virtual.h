#pragma once

#include <windows.h>
#include <stdio.h>

#include "util.h"
#include "pe_hdrs_helper.h"
#include "module_helper.h"

/**
Converts a raw PE supplied in a buffer to a virtual format.
If the executable flag is true (default), the PE file is loaded into executable memory.
Does not apply relocations. Does not load imports.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
*/
BYTE* pe_raw_to_virtual(const BYTE* rawPeBuffer, size_t rawPeSize, OUT size_t &outputSize, bool executable=true);

/**
Reads PE from the given file into memory and maps it into vitual format.
(Automatic raw to virtual conversion).
If the executable flag is true (default), the PE file is loaded into executable memory.
Does not apply relocations. Does not load imports.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
*/
BYTE* load_pe_module(char *filename, OUT size_t &v_size, bool executable=true);

