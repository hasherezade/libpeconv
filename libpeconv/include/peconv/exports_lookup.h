#pragma once
#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"
#include "exports_mapper.h"

#include <string>
#include <vector>
#include <map>

namespace peconv {

    //WARNING: doesn't work for the forwarded functions.
    FARPROC get_exported_func(PVOID modulePtr, LPSTR wanted_name);

    size_t get_exported_names(PVOID modulePtr, std::vector<std::string> &names_list);

    //function_resolver:
    class export_based_resolver : default_func_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

    //read the DLL name from the exports table:
    LPSTR read_dll_name(HMODULE modulePtr);

}; //namespace peconv
