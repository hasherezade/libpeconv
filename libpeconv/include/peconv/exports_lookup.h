#pragma once
#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"
#include "exports_mapper.h"

#include <string>
#include <vector>
#include <map>

namespace peconv {

    /**
    Gets the function address by the name. Uses Export Table lookup.
    WARNING: doesn't work for the forwarded functions.
    */
    FARPROC get_exported_func(PVOID modulePtr, LPSTR wanted_name);

    /**
    Gets list of all the functions from a given module that are exported by names.
    */
    size_t get_exported_names(PVOID modulePtr, std::vector<std::string> &names_list);

    /**
    Function resolver using Export Table lookup.
    */
    class export_based_resolver : default_func_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

    /**
    Read the DLL name from the Export Table.
    */
    LPSTR read_dll_name(HMODULE modulePtr);

}; //namespace peconv
