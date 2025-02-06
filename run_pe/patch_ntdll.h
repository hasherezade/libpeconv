#pragma once

#include <windows.h>

bool apply_ntdll_patch(HANDLE hProcess, LPVOID module_ptr);
