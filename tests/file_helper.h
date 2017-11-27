#pragma once

#include <Windows.h>
#include <stdio.h>

BYTE* load_file(char *filename, OUT size_t &r_size);
void free_file(BYTE* buffer, size_t buffer_size);
bool dump_to_file(char *out_path, BYTE* buffer, size_t buf_size);
