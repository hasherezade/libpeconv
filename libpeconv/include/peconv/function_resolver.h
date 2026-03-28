/**
* @file
* @brief   Definitions of basic Imports Resolver classes. They can be used for filling imports when the PE is loaded.
*/

#pragma once

#include <windows.h>
#include <string>
#include <map>

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

        virtual ~t_function_resolver() { }
    };

    /**
    A default functions resolver, using LoadLibraryA and GetProcAddress.
    */
    class default_func_resolver : public t_function_resolver {
        public:
        /**
        Get the address (VA) of the function with the given name, from the given DLL, using LoadLibraryA and GetProcAddress.
        \param func_name : the name of the function
        \param lib_name : the name of the DLL
        \return Virtual Address of the exported function
        */
        virtual FARPROC resolve_func(LPCSTR lib_name, LPCSTR func_name);

        /**
        Load the DLL using LoadLibraryA.
        \param lib_name : the name of the DLL
        \return base of the loaded module
        */
        virtual HMODULE load_library(LPCSTR lib_name);

        std::map<std::string, HMODULE> nameToModule;
    };

}; //namespace peconv
