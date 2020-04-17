/**
* @file
* @brief   Definitions of the used buffer types. Functions for their allocation and deallocation.
*/

#pragma once

#include <windows.h>

namespace peconv {

    /** 
    Validates pointers, checks if the particular field is inside the given buffer. Sizes must be given in bytes.
    */
    bool validate_ptr(
        IN const void* buffer_bgn, 
        IN SIZE_T buffer_size,
        IN const void* field_bgn,
        IN SIZE_T field_size
    );

//-----------------------------------------------------------------------------------
//
// supported buffers:
//
    /**
    A buffer allocated on the heap of a process, not aligned to the beginning of a memory page.
    */
    typedef PBYTE UNALIGNED_BUF;

    /**
    A buffer allocated in a virtual space of a process, aligned to the beginning of a memory page.
    */
    typedef PBYTE ALIGNED_BUF;

//
// alloc/free unaligned buffers:
//
     /** 
     Allocates a buffer on the heap. Can be used in the cases when the buffer does not have to start at the beginning of a page.
     */
    UNALIGNED_BUF alloc_unaligned(size_t buf_size);

    //
    /**
    Frees buffer allocated by alloc_unaligned.
    */
    void free_unaligned(UNALIGNED_BUF section_buffer);

//
// alloc/free aligned buffers:
//

    /**
    Allocates a buffer of a virtual memory (using VirtualAlloc).  Can be used in the cases when the buffer have to be aligned to the beginning of a page.
    */
    ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

    /**
    Frees buffer allocated by alloc_aligned.
    */
    bool free_aligned(ALIGNED_BUF buffer, size_t buffer_size=0);

    //PE buffers (wrappers)

    /**
    Allocates an aligned buffer for a PE file.
    */
    ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

    /**
    Free the memory allocated with alloc_pe_buffer.
    */
    bool free_pe_buffer(ALIGNED_BUF buffer, size_t buffer_size=0);

}; //namespace peconv
