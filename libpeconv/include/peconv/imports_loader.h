#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

namespace peconv {

    // callback function that will be executed by imports_walker when the next import was found
    typedef bool (*t_on_import_found) (
        BYTE* modulePtr, LPSTR lib_name, DWORD call_via, DWORD thunk_addr,
        t_function_resolver* func_resolver
        );

    bool imports_walker(BYTE* modulePtr, t_on_import_found callback, t_function_resolver* func_resolver);

    //fills handles of the mapped pe file using custom functions as LoadLibraryA and GetProcAddress
    bool load_imports(BYTE* modulePtr, t_function_resolver* func_resolver=NULL);

    bool has_valid_import_table(const PBYTE modulePtr, size_t moduleSize);

    // A valid name must contain printable characters. Empty name is also acceptable (may have been erased)
    bool is_valid_import_name(const PBYTE modulePtr, const size_t moduleSize, LPSTR lib_name);

}; // namespace peconv
