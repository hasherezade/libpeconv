/**
* @file
* @brief   Parsing and filling the Import Table.
*/

#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

namespace peconv {

    /**
    A callback that will be executed by imports_walker when the next import was found
    */
    typedef bool (*t_on_imports_found) (
        BYTE* modulePtr, 
        IMAGE_IMPORT_DESCRIPTOR* lib_desc,
        t_function_resolver* func_resolver
    );
    
    /**
    Walk through the table of imported DLLs (using the Import Table from Data Directory) and execute the callback each time when the new record was found
    */
    bool imports_walker(BYTE* modulePtr, t_on_imports_found on_functions_callback, t_function_resolver* func_resolver);

    /**
    Fills imports of the given PE with the help of the defined functions resolver.
    */
    bool load_imports(BYTE* modulePtr, t_function_resolver* func_resolver=nullptr);

    /**
    Checks if the given PE has a valid import table.
    */
    bool has_valid_import_table(const PBYTE modulePtr, size_t moduleSize);

    /**
    Checks if the given lib_name is a valid DLL name.
    A valid name must contain printable characters. Empty name is also acceptable (may have been erased).
    */
    bool is_valid_import_name(const PBYTE modulePtr, const size_t moduleSize, LPSTR lib_name);

}; // namespace peconv
