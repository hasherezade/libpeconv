#pragma once

#include <windows.h>
#include <stdio.h>

#include "util.h"
#include "pe_hdrs_helper.h"
#include "module_helper.h"

// Map raw PE into virtual memory of local process:
bool sections_raw_to_virtual(const BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress);

// Converts raw image to virtual. Does not apply relocations.
BYTE* pe_raw_to_virtual(const BYTE* payload, size_t in_size, OUT size_t &out_size, bool executable=true);

// Maps PE into memory (raw to virtual). Does not apply relocations. 
BYTE* load_pe_module(char *filename, OUT size_t &v_size, bool executable=true);

