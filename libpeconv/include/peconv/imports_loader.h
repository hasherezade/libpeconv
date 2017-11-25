#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"

namespace peconv {

//fills handles of the mapped pe file
bool load_imports(PVOID modulePtr);

}; // namespace peconv