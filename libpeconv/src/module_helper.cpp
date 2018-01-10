#include "peconv/module_helper.h"

#include <iostream>

peconv::UNALIGNED_BUF peconv::alloc_unaligned(size_t buf_size)
{
    PBYTE buf = (PBYTE) calloc(buf_size, sizeof(BYTE));
    return buf;
}

void peconv::free_unaligned(peconv::UNALIGNED_BUF section_buffer)
{
    free(section_buffer);
}

peconv::ALIGNED_BUF peconv::alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    PBYTE buf = (PBYTE) VirtualAlloc((LPVOID) desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    return buf;
}

// Free loaded module (wrapper)
bool peconv::free_aligned(peconv::ALIGNED_BUF buffer, size_t buffer_size)
{
    if (buffer == NULL) return true;
    if (!VirtualFree(buffer, 0, MEM_RELEASE)) {
        std::cerr << "Releasing failed" << std::endl;
        return false;
    }
    return true;
}

//wrappers

peconv::ALIGNED_BUF peconv::alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    return alloc_aligned(buffer_size, protect, desired_base);
}

//-----------------------------------------------------------------------------------

// Free loaded module (wrapper)
bool peconv::free_pe_buffer(peconv::ALIGNED_BUF buffer, size_t buffer_size)
{
    return peconv::free_aligned(buffer, buffer_size);
}

peconv::UNALIGNED_BUF peconv::alloc_pe_section(size_t buf_size)
{
    return peconv::alloc_unaligned(buf_size);
}

void peconv::free_pe_section(peconv::UNALIGNED_BUF section_buffer)
{
    return peconv::free_unaligned(section_buffer);
}
