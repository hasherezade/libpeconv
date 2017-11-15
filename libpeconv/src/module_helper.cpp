#include "module_helper.h"

void free_pe_module(BYTE* buffer, size_t buffer_size)
{
    VirtualFree(buffer, buffer_size, MEM_RELEASE);
}

