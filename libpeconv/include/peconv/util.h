#pragma once

#include "file_util.h"
#include "resource_util.h"

namespace peconv {
    /**
    Checks if the given buffer is fully filled with the specified character.
    \param cave_ptr : pointer to the buffer to be checked
    \param cave_size : size of the buffer to be checked
    \param padding_char : the required character
    */
    bool is_padding(BYTE *cave_ptr, size_t cave_size, const BYTE padding_char);
};

