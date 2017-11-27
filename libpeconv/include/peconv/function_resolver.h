#pragma once

#include <Windows.h>

namespace peconv {
    
    class t_function_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name) = 0;
    };

    class default_func_resolver : t_function_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

}; //namespace peconv
