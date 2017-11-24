#pragma once

#include <Windows.h>
#include <stdio.h>

#include <peconv/module_helper.h>

BYTE* load_resource_data(OUT size_t &out_size, int res_id);

void free_resource_data(BYTE *buffer, size_t buffer_size);
