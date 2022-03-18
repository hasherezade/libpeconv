/**
* @file
* @brief   Functions for retrieving process information from PEB.
*/

#pragma once

#include <windows.h>

namespace peconv {

    /**
    Gets handle to the given module via PEB. A low-level equivalent of `GetModuleHandleW`.
    \param module_name : (optional) the name of the DLL loaded within the current process. If not set, the main module of the current process is used.
    \return the handle of the DLL with given name, or, if the name was not given, the handle of the main module of the current process.
    */
    HMODULE get_module_via_peb(IN OPTIONAL LPCWSTR module_name = nullptr);


    /**
    Gets size of the given module via PEB.
    \param hModule : (optional) the base of the module which's size we want to retrieve. If not set, the main module of the current process is used.
    \return the size of the given module.
    */
    size_t get_module_size_via_peb(IN OPTIONAL HMODULE hModule = nullptr);

    /**
    Sets the given module as the main module in the current PEB.
    \param hModule : the module to be connected to the current PEB.
    \return true if succeeded, false if failed
    */
    bool set_main_module_in_peb(HMODULE hModule);

    /**
    Gets the main module from the current PEB.
    \return the main module connected to the current PEB.
    */
    HMODULE get_main_module_via_peb();
};

