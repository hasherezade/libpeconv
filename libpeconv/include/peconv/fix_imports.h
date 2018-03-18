#pragma once

#include <Windows.h>

#include <string>

#include <set>
#include <map>

#include <iterator>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"
#include "exports_mapper.h"

#define MIN_DLL_LEN 5

namespace peconv {

    class ImportedDllCoverage
    {
    public:
        ImportedDllCoverage(std::set<ULONGLONG>& _addresses, peconv::ExportsMapper& _exportsMap)
            : addresses(_addresses), exportsMap(_exportsMap)
        {
        }

        bool findCoveringDll();

        bool mapAddressesToFunctions(std::string dll);

        std::map<ULONGLONG, std::set<ExportedFunc>> addrToFunc;
        std::string dllName;

    protected:
        std::set<ULONGLONG> &addresses;
        peconv::ExportsMapper& exportsMap;
    };

    bool fix_imports(PVOID modulePtr, size_t moduleSize, peconv::ExportsMapper& exportsMap);
}
