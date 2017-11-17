#pragma once

#include <Windows.h>
#include <stdio.h>

BYTE* load_file(char *filename, OUT size_t &r_size);
void free_file(BYTE* buffer, size_t buffer_size);
