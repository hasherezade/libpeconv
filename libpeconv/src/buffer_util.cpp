#include "peconv/buffer_util.h"

#include <iostream>

//
// validate pointer:
//

bool peconv::validate_ptr(IN const void* buffer_bgn, IN SIZE_T buffer_size, IN const void* field_bgn, IN SIZE_T field_size)
{
    if (buffer_bgn == nullptr || field_bgn == nullptr) {
        return false;
    }
    ULONGLONG start = (ULONGLONG)buffer_bgn;
    ULONGLONG end = start + buffer_size;

    ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

    if ((ULONGLONG)field_bgn < start) {
        return false;
    }
    if (field_end > end) {
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------------
//
// alloc/free unaligned buffers:
//

//allocates a buffer that does not have to start from the beginning of the section
peconv::UNALIGNED_BUF peconv::alloc_unaligned(size_t buf_size)
{
    PBYTE buf = (PBYTE) calloc(buf_size, sizeof(BYTE));
    return buf;
}

void peconv::free_unaligned(peconv::UNALIGNED_BUF section_buffer)
{
    free(section_buffer);
}

//
// alloc/free aligned buffers:
//

peconv::ALIGNED_BUF peconv::alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    PBYTE buf = (PBYTE) VirtualAlloc((LPVOID) desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    return buf;
}

bool peconv::free_aligned(peconv::ALIGNED_BUF buffer, size_t buffer_size)
{
    if (buffer == nullptr) return true;
    if (!VirtualFree(buffer, 0, MEM_RELEASE)) {
#ifdef _DEBUG
        std::cerr << "Releasing failed" << std::endl;
#endif
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------------
//
// wrappers using appropriate buffer type according to the purpose:
//

// allocate a buffer for PE module:
peconv::ALIGNED_BUF peconv::alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    return alloc_aligned(buffer_size, protect, desired_base);
}


// Free loaded PE module
bool peconv::free_pe_buffer(peconv::ALIGNED_BUF buffer, size_t buffer_size)
{
    return peconv::free_aligned(buffer, buffer_size);
}

// allocate a buffer for PE section:

peconv::UNALIGNED_BUF peconv::alloc_pe_section(size_t buf_size)
{
    return peconv::alloc_unaligned(buf_size);
}

void peconv::free_pe_section(peconv::UNALIGNED_BUF section_buffer)
{
    return peconv::free_unaligned(section_buffer);
}

