#pragma once

#include <windows.h>

namespace peconv {

bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);

// Write a buffer into a file:
bool dump_to_file(const char *out_path, PBYTE dump_data, size_t dump_size);

// Read raw file content. Automatically allocate a buffer of a required size.
PBYTE read_from_file(const char *in_path, size_t &read_size);

} //namespace peconv
