#include "peconv/function_resolver.h"

#include <iostream>

FARPROC peconv::default_func_resolver::resolve_func(LPCSTR lib_name, LPCSTR func_name)
{
    HMODULE libBasePtr = LoadLibraryA(lib_name);
    if (libBasePtr == NULL) {
        std::cerr << "Could not load the library: " << lib_name << std::endl;
        return NULL;
    }
    FARPROC hProc = GetProcAddress(libBasePtr, func_name);
    if (hProc == NULL) {
        ULONGLONG func_val = (ULONGLONG)func_name;
        //is only the first WORD filled?
        bool is_ord = (func_val & (0x0FFFF)) == func_val;
        std::cerr << "Could not load the function: " << lib_name << ".";
        if (is_ord) {
            std::cerr << std::hex << "0x" << func_val;
        }
        else {
            std::cerr << func_name;
        }
        std::cerr << std::endl;
        return NULL;
    }
    return hProc;
}
