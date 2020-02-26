#pragma once

#include <Windows.h>

namespace peconv {

    // Gets handle to the given module via PEB. A low-level equivalent of GetModuleHandle.
    HMODULE get_module_via_peb(LPWSTR module_name);
};

