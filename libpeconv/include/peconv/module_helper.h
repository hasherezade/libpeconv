#pragma once

#include <Windows.h>

namespace peconv {

    //validates pointers,  checks if the particular field is inside the given buffer
    bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);

//-----------------------------------------------------------------------------------
//
// supported buffers:
//
    typedef PBYTE UNALIGNED_BUF; // not aligned to the beginning of section
    typedef PBYTE ALIGNED_BUF; //always starting from the beginning of the new section

//
// alloc/free unaligned buffers:
//
    //allocates a buffer that does not have to start from the beginning of the section
    UNALIGNED_BUF alloc_unaligned(size_t buf_size);

    //frees buffer allocated by alloc_unaligned:
    void free_unaligned(UNALIGNED_BUF section_buffer);

//
// alloc/free aligned buffers:
//

    //allocates buffer starting from the beginning of the section (this function is a wrapper for VirtualAlloc)
    ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

    //frees buffer allocated by alloc_alligned:
    bool free_aligned(ALIGNED_BUF buffer, size_t buffer_size=0);

    //PE buffers (wrappers)

    ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

    // Free loaded module (wrapper)
    bool free_pe_buffer(ALIGNED_BUF buffer, size_t buffer_size=0);

    UNALIGNED_BUF alloc_pe_section(size_t buf_size);

    void free_pe_section(UNALIGNED_BUF section_buffer);

}; //namespace peconv
