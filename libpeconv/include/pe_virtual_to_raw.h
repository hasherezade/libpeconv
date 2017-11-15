#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"
#include "module_helper.h"

// Maps virtual image of PE to into raw. If rebuffer is set (default), the input buffer is not modified. Automaticaly applies relocations.
BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size, bool rebuffer=true);
