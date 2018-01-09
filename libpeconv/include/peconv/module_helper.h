#pragma once

#include <Windows.h>

namespace peconv {

// Aligned buffers - starting from the beginning of the new section£
typedef PBYTE UNALIGNED_BUF;

UNALIGNED_BUF alloc_unaligned(size_t buf_size);

void free_unaligned(UNALIGNED_BUF section_buffer);

// Unaligned buffers - not aligned to the beginning of section:
typedef PBYTE ALIGNED_BUF;

ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

bool free_aligned(ALIGNED_BUF buffer, size_t buffer_size);


//PE buffers (wrappers)
//TODO: implement a class for module management

ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

// Free loaded module (wrapper)
bool free_pe_buffer(ALIGNED_BUF buffer, size_t buffer_size);

UNALIGNED_BUF alloc_pe_section(size_t buf_size);

void free_pe_section(UNALIGNED_BUF section_buffer);

}; //namespace peconv
