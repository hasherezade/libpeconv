/**
* @file
* @brief   Converting PE from virtual to raw format.
*/

#pragma once

#include <windows.h>

#include "buffer_util.h"

namespace peconv {

    /**
    Maps virtual image of PE to into raw. Automaticaly applies relocations.
    Automatically allocates buffer of the needed size (the size is returned in outputSize).
    \param payload : the PE in the Virtual format that needs to be converted into the Raw format
    \param in_size : size of the input buffer (the PE in the Virtual format)
    \param loadBase : the base to which the given PE was relocated
    \param outputSize : the size of the output buffer (the PE in the Raw format)
    \param rebuffer : if set (default), the input buffer is rebuffered and the original buffer is not modified.
    \return a buffer of the outputSize, containing the Raw PE. The buffer can be freed by the function free_pe_module.
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
    \param payload : the PE in the Virtual format that needs to be realigned
    \param in_size : size of the input buffer
    \param loadBase : the base to which the given PE was relocated
    \param outputSize : the size of the output buffer (the PE in the Raw format)
    \return a buffer of the outputSize, containing the realigned PE. The buffer can be freed by the function free_pe_module.
    */
    BYTE* pe_realign_raw_to_virtual(
        IN const BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize
    );

};//namespace peconv
