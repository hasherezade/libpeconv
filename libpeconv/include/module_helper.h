#pragma once

#include <Windows.h>

// Free loaded module (wrapper)
void free_pe_module(BYTE* buffer, size_t buffer_size);
