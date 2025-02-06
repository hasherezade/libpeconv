#pragma once

#include <windows.h>

bool patch_NtManageHotPatch32(HANDLE hProcess);
bool patch_NtManageHotPatch64(HANDLE hProcess);
bool patch_ZwQueryVirtualMemory(HANDLE hProcess, LPVOID module_ptr);
