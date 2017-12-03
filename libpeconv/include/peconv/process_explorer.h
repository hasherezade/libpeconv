#pragma once

#include "Windows.h"
#include <TlHelp32.h>

#include <map>

namespace peconv {

    size_t enum_modules_in_process(std::map<ULONGLONG, MODULEENTRY32> &modulesMap, DWORD process_id=0);

    HMODULE get_module_containing(ULONGLONG address, DWORD process_id=0);

}; //namespace peconv