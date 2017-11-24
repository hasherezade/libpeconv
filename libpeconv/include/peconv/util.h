#pragma once

#include <windows.h>

namespace peconv {

bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);

} //namespace peconv