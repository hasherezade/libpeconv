/**
* @file
* @brief   Definitions of basic Imports Resolver classes. They can be used for filling imports when the PE is loaded.
*/

#pragma once

#include <windows.h>

namespace peconv {
    /**
    A base class for functions resolver.
    */
    class t_function_resolver {
        public:
        /**
        Get the address (VA) of the function with the given name, from the given DLL.
        \param func_name : the name of the function
        \param lib_name : the name of the DLL
        \return Virtual Address of the exported function
        */
        virtual FARPROC resolve_func(LPCSTR lib_name, LPCSTR func_name) = 0;
    };

    /**
    A default functions resolver, using LoadLibraryA and GetProcAddress.
    */
    class default_func_resolver : t_function_resolver {
        public:
        /**
        Get the address (VA) of the function with the given name, from the given DLL, using LoadLibraryA and GetProcAddress.
        \param func_name : the name of the function
        \param lib_name : the name of the DLL
        \return Virtual Address of the exported function
        */
        virtual FARPROC resolve_func(LPCSTR lib_name, LPCSTR func_name);
    };

}; //namespace peconv
