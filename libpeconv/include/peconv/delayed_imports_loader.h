#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

namespace peconv {

    IMAGE_DELAYLOAD_DESCRIPTOR* get_delayed_imps(IN const BYTE* modulePtr, IN const size_t moduleSize, OUT size_t &dir_size);

    // moduleBase is a base to which the module was relocated, it may (or not) be the same as modulePtr
    bool load_delayed_imports(BYTE* modulePtr, const ULONGLONG moduleBase, t_function_resolver* func_resolver = nullptr);

}; // namespace peconv
