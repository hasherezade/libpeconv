#pragma once

#include <windows.h>
#include <stdio.h>

#include "module_helper.h"

namespace peconv {

/**
Converts a raw PE supplied in a buffer to a virtual format.
If the executable flag is true (default), the PE file is loaded into executable memory.
Does not apply relocations. Does not load imports.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
If the desired_base is defined (NULL by default), it enforces allocation at the particular base.
*/
BYTE* pe_raw_to_virtual(const BYTE* rawPeBuffer, size_t rawPeSize, OUT size_t &outputSize, bool executable=true, ULONGLONG desired_base=NULL);

}; // namespace peconv