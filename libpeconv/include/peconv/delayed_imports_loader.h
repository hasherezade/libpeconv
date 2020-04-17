/**
* @file
* @brief   Parsing and filling the Delayload Import Table.
*/

#pragma once

#include <windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

#if (defined(_WIN32_WINNT) && _WIN32_WINNT > 0x0601) || __MINGW32__ //Windows SDK version 6.1 (Windows 7)
#define DELAYLOAD_IMPORTS_DEFINED
#endif

#ifndef DELAYLOAD_IMPORTS_DEFINED
#include "pshpack4.h"

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaBased : 1;             // Delay load version 2
            DWORD ReservedAttributes : 31;
        } DUMMYSTRUCTNAME;
    } Attributes;

    DWORD DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string)
    DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE)
    DWORD ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
    DWORD ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
    DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
    DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
    DWORD TimeDateStamp;                    // 0 if not bound,
                                            // Otherwise, date/time of the target DLL

} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

typedef const IMAGE_DELAYLOAD_DESCRIPTOR *PCIMAGE_DELAYLOAD_DESCRIPTOR;

#include "poppack.h"
#endif

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
