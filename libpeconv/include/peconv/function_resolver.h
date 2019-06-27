#pragma once

#include <Windows.h>

namespace peconv {
    /**
    A base class for functions resolver.
    */
    class t_function_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name) = 0;
    };

    /**
    A default functions resolver, using LoadLibraryA and GetProcAddress.
    */
    class default_func_resolver : t_function_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

}; //namespace peconv
