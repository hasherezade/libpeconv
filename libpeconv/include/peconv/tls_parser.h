/**
* @file
* @brief   Functions related to TLS Callbacks
*/

#pragma once

#include <windows.h>
#include<vector>

namespace peconv {

    /**
    A function listing RVAs of all TLS callbacks that are present in the given module.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format, relocated to the load base
    \param moduleSize : size of the given module (if 0 given, the imageSize from the PE headers will be used)
    \param callbacks_RVAs : a vector of DWORDs, that will be filled with the callbacks
    */
    size_t list_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize, OUT std::vector<DWORD> &callbacks_RVAs);

    /**
    A function running all the TLS callbacks that are present in the given module, one by one.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format, relocated to the load base
    \param moduleSize : size of the given module (if 0 given, the imageSize from the PE headers will be used)
    \param dwReason : a parameter (dwReason) that will be passed to the callback function
    */
    size_t run_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize=0, IN DWORD dwReason = DLL_PROCESS_ATTACH);

}; //namespace peconv
