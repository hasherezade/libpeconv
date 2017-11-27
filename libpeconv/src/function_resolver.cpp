#include "peconv/function_resolver.h"

#include <iostream>

FARPROC peconv::default_func_resolver::resolve_func(LPSTR lib_name, LPSTR func_name)
{
    HMODULE libBasePtr = LoadLibraryA(lib_name);
    if (libBasePtr == NULL) {
        std::cerr << "Could not load the library!" << std::endl;
        return NULL;
    }
    FARPROC hProc = GetProcAddress(libBasePtr, func_name);
    if (hProc == NULL) {
        std::cerr << "Could not load the function!" << std::endl;
        return NULL;
    }
    return hProc;
}
