#include "resource_helper.h"

#include <peconv/module_helper.h>

BYTE* load_resource_data(OUT size_t &out_size, int res_id)
{
    HMODULE hInstance = GetModuleHandle(NULL);
    HRSRC res = FindResource(hInstance, MAKEINTRESOURCE(res_id), RT_RCDATA);
    if (!res) return NULL;

    HGLOBAL res_handle  = LoadResource(NULL, res);
    if (res_handle == NULL) return NULL;

    BYTE* res_data = (BYTE*) LockResource(res_handle);
    out_size = static_cast<size_t>(SizeofResource(NULL, res));

    BYTE* out_buf = peconv::alloc_aligned(out_size, PAGE_READWRITE);
    memcpy(out_buf, res_data, out_size);

    FreeResource(res_handle);
    return out_buf;
}

void free_resource_data(BYTE *buffer, size_t buffer_size)
{
    peconv::free_aligned(buffer, buffer_size);
}
