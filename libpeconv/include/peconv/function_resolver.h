#pragma once

#include <Windows.h>

namespace peconv {

    typedef FARPROC (*t_function_resolver)(LPSTR lib_name, LPSTR func_name);

    //t_function_resolver
    FARPROC default_func_resolver(LPSTR lib_name, LPSTR func_name);

}; //namespace peconv
