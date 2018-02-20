#include "peconv/resource_util.h"

peconv::ALIGNED_BUF peconv::load_resource_data(OUT size_t &out_size, int res_id, const LPSTR res_type)
{
    HMODULE hInstance = GetModuleHandleA(NULL);
    HRSRC res = FindResourceA(hInstance, MAKEINTRESOURCE(res_id), res_type);
    if (!res) return nullptr;

    HGLOBAL res_handle  = LoadResource(hInstance, res);
    if (res_handle == nullptr) return nullptr;

    BYTE* res_data = (BYTE*) LockResource(res_handle);
    size_t r_size = static_cast<size_t>(SizeofResource(hInstance, res));
    if (out_size != 0 && out_size <= r_size) {
        r_size = out_size;
    }

    peconv::ALIGNED_BUF out_buf = peconv::alloc_aligned(r_size, PAGE_READWRITE);
    if (out_buf != nullptr) {
        memcpy(out_buf, res_data, r_size);
        out_size = r_size;
    } else {
        out_size = 0;
    }
    FreeResource(res_handle);
    return out_buf;
}

void peconv::free_resource_data(peconv::ALIGNED_BUF buffer)
{
    peconv::free_aligned(buffer);
}
