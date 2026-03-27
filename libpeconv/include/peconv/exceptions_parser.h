/**
* @file
* @brief   Functions related to Exceptions Table
*/

#pragma once

#ifdef _MSC_VER
#define PECONV_FORCEINLINE __forceinline
#define PECONV_TRY_EXCEPT_BLOCK_START __try
#define PECONV_TRY_EXCEPT_BLOCK_END __except (EXCEPTION_EXECUTE_HANDLER)
#else
#define PECONV_FORCEINLINE __attribute__((always_inline)) inline
#define PECONV_TRY_EXCEPT_BLOCK_START try
#define PECONV_TRY_EXCEPT_BLOCK_END catch (...)
#endif

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
