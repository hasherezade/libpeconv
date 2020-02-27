/**
* @file
* @brief   Functions for retrieving process information from PEB.
*/

#pragma once

#include <Windows.h>

namespace peconv {

    /**
    Gets handle to the given module via PEB. A low-level equivalent of `GetModuleHandleW`.
    \param module_name : (optional) the name of the DLL loaded within the current process.
    \return the handle of the DLL with given name, or, if the name was not given, the handle of the main module of the current process.
    */
    HMODULE get_module_via_peb(IN OPTIONAL LPWSTR module_name);
};

