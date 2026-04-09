/**
* @file
* @brief   Functions related to TLS Callbacks
*/

#pragma once

#include <windows.h>
#include<vector>
#include<unordered_set>

namespace peconv {

    /**
    A function listing RVAs of all TLS callbacks that are present in the given module.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format, relocated to the load base
    \param moduleSize : size of the given module (if 0 given, the imageSize from the PE headers will be used)
    \param tls_callbacks : a vector of TLS callbacks addresses (as given in the TLS table)
    \param relocs : cached list of relocations (optional). Used for RVA/VA conversion. If nullptr is passed, the function will try to collect the set internally (if reloc table exists).
    \return number of TLS callbacks added to the list
    */
    size_t list_tls_callbacks(IN PBYTE modulePtr, IN size_t moduleSize, OUT std::vector<ULONGLONG> &tls_callbacks, IN std::unordered_set<ULONGLONG>* relocs);

    /**
    A function running all the TLS callbacks that are present in the given module, one by one.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format, relocated to the load base
    \param moduleSize : size of the given module (if 0 given, the imageSize from the PE headers will be used)
    \param dwReason : a parameter (dwReason) that will be passed to the callback function
    \return number of TLS callbacks executed
    */
    size_t run_tls_callbacks(IN PBYTE modulePtr, IN size_t moduleSize=0, IN DWORD dwReason = DLL_PROCESS_ATTACH);

}; //namespace peconv
