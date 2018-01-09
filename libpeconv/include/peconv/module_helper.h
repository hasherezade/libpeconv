#pragma once

#include <Windows.h>

namespace peconv {

//TODO: implement a class for module management

BYTE* alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base=NULL);

// Free loaded module (wrapper)
bool free_pe_buffer(BYTE* buffer, size_t buffer_size);

BYTE* alloc_pe_section(size_t buf_size);

void free_pe_section(BYTE *section_buffer);

}; //namespace peconv
