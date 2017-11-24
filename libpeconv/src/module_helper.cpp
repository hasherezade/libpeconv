#include "module_helper.h"

BYTE* peconv::alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    return (BYTE*) VirtualAlloc((LPVOID) desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
}

void peconv::free_pe_buffer(BYTE* buffer, size_t buffer_size)
{
    if (buffer == NULL) return;
    VirtualFree(buffer, buffer_size, MEM_DECOMMIT);
}

