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
        IN BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize,
        IN OPTIONAL bool rebuffer=true
    );

    /*
    Modifies raw alignment of the PE to be the same as virtual alignment.
    */
    BYTE* pe_realign_raw_to_virtual(
        IN const BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize
    );

};//namespace peconv
