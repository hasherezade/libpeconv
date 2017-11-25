#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"

namespace peconv {

    //function used as GetProcAddress:
    typedef FARPROC _stdcall t_get_proc_address(HMODULE hModule, LPCSTR lpProcName);

    //function used as LoadLibraryA:
    typedef HMODULE _stdcall t_load_library(LPCSTR lpLibFileName);

    // callback function that will be executed by imports_walker when the next import was found
    typedef bool (*t_on_import_found) (
        LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, BYTE* modulePtr,
        t_load_library load_lib, 
        t_get_proc_address get_proc_addr
        );

    bool write_handle(BYTE* modulePtr, ULONGLONG call_via, HMODULE libBasePtr, LPSTR func_name, t_get_proc_address get_proc_addr);

    bool imports_walker(BYTE* modulePtr, t_on_import_found callback, t_load_library load_lib,  t_get_proc_address get_proc_addr);

    //fills handles of the mapped pe file using custom functions as LoadLibraryA and GetProcAddress
    bool load_imports(BYTE* modulePtr, t_load_library load_lib,  t_get_proc_address get_proc_addr);

    //plain, simple imports loader: using standard LoadLibraryA and GetProcAddress
    bool load_imports(BYTE* modulePtr);

}; // namespace peconv

