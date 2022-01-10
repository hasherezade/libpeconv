/**
* @file
* @brief   Functions related to TLS Callbacks
*/

#pragma once

#include <windows.h>
#include<vector>

namespace peconv {

    /**
    A helper function, normalizing virtual addresses. It automatically detects if the given virtual address is VA or RVA, and converts it into RVA
    \param imgBase : the base address to which the module was relocated
    \param imgSize : the size of the image
    \param virtualAddr : the virtual address (RVA or VA) that we want to convert (within the module described by imgBase and imgSize)
    \param outRVA : the output of the conversion (RVA)
    \return true if the conversion was successful, false otherwise
    */
    bool virtual_addr_to_rva(IN const ULONGLONG imgBase, IN const DWORD imgSize, IN ULONGLONG virtualAddr, OUT DWORD &outRVA);

    /**
    A function listing RVAs of all TLS callbacks that are present in the given module.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format, relocated to the load base
    \param moduleSize : size of the given module (if 0 given, the imageSize from the PE headers will be used)
    \param tls_callbacks : a vector of TLS callbacks addresses (as given in the TLS table)
    \return number of TLS callbacks added to the list
    */
    size_t list_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize, OUT std::vector<ULONGLONG> &tls_callbacks);

    /**
    A function running all the TLS callbacks that are present in the given module, one by one.
    \param modulePtr : pointer to the buffer with the PE in a Virtual format, relocated to the load base
    \param moduleSize : size of the given module (if 0 given, the imageSize from the PE headers will be used)
    \param dwReason : a parameter (dwReason) that will be passed to the callback function
    \return number of TLS callbacks executed
    */
    size_t run_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize=0, IN DWORD dwReason = DLL_PROCESS_ATTACH);

}; //namespace peconv
