#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"

bool write_handle(LPCSTR lib_name, ULONGLONG call_via, LPSTR func_name, LPVOID modulePtr, bool is64);

//fills handles of the mapped pe file
bool load_imports(PVOID modulePtr);