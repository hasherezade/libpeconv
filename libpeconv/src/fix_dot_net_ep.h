#pragma once

#include <windows.h>

bool fix_dot_net_ep(BYTE *pe_buffer, size_t pe_buffer_size);
bool is_dot_net(BYTE *pe_buffer, size_t pe_buffer_size);

BYTE* search_jump(BYTE *buf, size_t buf_size, const DWORD cor_exe_main_thunk, const ULONGLONG img_base);
