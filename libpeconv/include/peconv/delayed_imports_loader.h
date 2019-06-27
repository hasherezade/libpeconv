#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

namespace peconv {

    /**
    Get the Delayload Imports directory. Returns the pointer to the first descriptor. The size of the directory is passed via variable dir_size.
    */
    IMAGE_DELAYLOAD_DESCRIPTOR* get_delayed_imps(IN const BYTE* modulePtr, IN const size_t moduleSize, OUT size_t &dir_size);

    /**
    Fill the Delayload Imports in the given module.
    \param modulePtr : the pointer to the module where the imports needs to be filled.
    \param moduleBase : the base to which the module was relocated, it may (or not) be the same as modulePtr
    \param func_resolver : the resolver that will be used for loading the imports
    \return : true if resolving all succeeded, false otherwise
    */
    bool load_delayed_imports(BYTE* modulePtr, const ULONGLONG moduleBase, t_function_resolver* func_resolver = nullptr);

}; // namespace peconv
