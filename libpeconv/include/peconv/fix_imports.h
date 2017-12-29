#pragma once

#include <Windows.h>
#include <string>
#include <map>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"
#include "exports_mapper.h"

namespace peconv {
    bool fix_imports(PVOID modulePtr, size_t moduleSize, peconv::ExportsMapper& exportsMap);
}
