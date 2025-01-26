#pragma once

#include <windows.h>

bool apply_ntdll_patch64(HANDLE hProcess, LPVOID module_ptr);
