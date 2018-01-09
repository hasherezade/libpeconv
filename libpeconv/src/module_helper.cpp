#include "peconv/module_helper.h"

#include <iostream>

BYTE* peconv::alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    PBYTE buffer = (BYTE*) VirtualAlloc((LPVOID) desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    return buffer;
}

bool peconv::free_pe_buffer(BYTE* buffer, size_t buffer_size)
{
    if (buffer == NULL) return true;
    if (!VirtualFree(buffer, buffer_size, MEM_DECOMMIT)) {
        return false;
    }
    return true;
}

BYTE* peconv::alloc_pe_section(size_t buf_size)
{
    return (BYTE*) calloc(buf_size, sizeof(BYTE));
}

void peconv::free_pe_section(BYTE *section_buffer)
{
    free(section_buffer);
}

