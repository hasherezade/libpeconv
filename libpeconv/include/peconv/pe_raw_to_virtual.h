#pragma once

#include <windows.h>
#include <stdio.h>

#include "buffer_util.h"

namespace peconv {

    /**
    Converts a raw PE supplied in a buffer to a virtual format.
    If the executable flag is true (default), the PE file is loaded into executable memory.
    Does not apply relocations. Does not load imports.
    Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
    If the desired_base is defined (0 by default), it enforces allocation at the particular base.
    */
    BYTE* pe_raw_to_virtual(
        _In_reads_(rawPeSize) const BYTE* rawPeBuffer,
        _In_ size_t rawPeSize,
        _Out_ size_t &outputSize,
        _In_opt_ bool executable = true,
        _In_opt_ ULONGLONG desired_base = 0
    );

}; // namespace peconv
