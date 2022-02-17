/**
* @file
* @brief   Functions related to Exceptions Table
*/

#pragma once

#include "peconv/buffer_util.h"

namespace peconv {

#ifdef _WIN64
    /**
    Allows to activate the Exception table from the manually loaded module. Works only for 64-bit PEs.
    */
    bool setup_exceptions(IN BYTE* modulePtr, IN size_t moduleSize);
#endif

};

