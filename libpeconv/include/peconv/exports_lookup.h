#pragma once
#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

namespace peconv {

    //WARNING: this is an unfinished version - resolves only functions imported by names.
    // Doesn't work for the forwarded functions.
    FARPROC get_exported_func(PVOID modulePtr, LPSTR wanted_name);

    //function_resolver:
    class export_based_resolver : default_func_resolver {
        public:
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

}; //namespace peconv
