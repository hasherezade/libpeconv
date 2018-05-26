#pragma once

#include <Windows.h>

DWORD calc_checksum(char *str, bool enable_tolower);
DWORD calc_checksum(BYTE *str, size_t buf_size, bool enable_tolower);

