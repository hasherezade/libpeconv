#pragma once

#include <Windows.h>

namespace peconv {
    // Try to find a base to which the PE file was relocated, basing on the relocations.
    // WARNING: sometimes it may give inaccurate results
    ULONGLONG find_base_candidate(BYTE *buf, size_t buf_size);
};
