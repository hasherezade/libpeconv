/**
* @file
* @brief   Functions related to Exceptions Table
*/

#pragma once

#include "peconv/buffer_util.h"

namespace peconv {

    /**
    Allows to activate the Exception table from the manually loaded module.
    For 32-bits the loaded image should enable /SAFESEH linker option,
    otherwise the exception handler cannot pass the RtlIsValidHandler() check
    when an exception occurs
    */
    bool setup_exceptions(IN BYTE* modulePtr, IN size_t moduleSize);

};

