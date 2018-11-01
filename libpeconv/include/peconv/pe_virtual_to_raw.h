#pragma once

#include <windows.h>

#include "buffer_util.h"

namespace peconv {

    /**
    Maps virtual image of PE to into raw.
    If rebuffer is set (default), the input buffer is rebuffered and the original buffer is not modified. 
    Automaticaly applies relocations.
    Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
    */
    BYTE* pe_virtual_to_raw(
        _In_reads_bytes_(in_size) BYTE* payload, 
        _In_ size_t in_size,
        _In_ ULONGLONG loadBase,
        _Out_ size_t &outputSize,
        _In_opt_ bool rebuffer=true
    );

    /*
    Modifies raw alignment of the PE to be the same as virtual alignment.
    */
    BYTE* pe_realign_raw_to_virtual(
        _In_reads_bytes_(in_size) const BYTE* payload, 
        _In_ size_t in_size,
        _In_ ULONGLONG loadBase,
        _Out_ size_t &outputSize
    );

};//namespace peconv
