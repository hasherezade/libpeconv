#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"
#include "module_helper.h"

/**
Maps virtual image of PE to into raw.
If rebuffer is set (default), the input buffer is rebuffered and the original buffer is not modified. 
Automaticaly applies relocations.
Automatically allocates buffer of the needed size (the size is returned in outputSize). The buffer can be freed by the function free_pe_module.
*/
BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &outputSize, bool rebuffer=true);

