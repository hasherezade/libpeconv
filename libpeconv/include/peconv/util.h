#pragma once

#include "file_util.h"
#include "resource_util.h"

namespace peconv {
    bool is_padding(BYTE *cave_ptr, size_t cave_size, const BYTE padding_char);
};

