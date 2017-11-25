#pragma once
#include <Windows.h>

#include "peconv/pe_hdrs_helper.h"

namespace peconv {

    //WARNING: this is an unfinished version - resolves only functions imported by names.
    // Doesn't work for the forwarded functions.
    PVOID get_exported_func(PVOID modulePtr, LPSTR wanted_name);

}; //namespace peconv
