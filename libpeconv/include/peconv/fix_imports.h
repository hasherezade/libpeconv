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

    //fix imports in the given module, using the given map of all available exports
    bool fix_imports(PVOID modulePtr, size_t moduleSize, peconv::ExportsMapper& exportsMap);
    
    // a helper class that allows to find out where the functions are imported from
    class ImportedDllCoverage
    {
    public:
        //_addresses: the list of filled imports (VAs)
        //_exportsMap: the map of the exports of all loaded DLLs (the space in which we will be searching)
        ImportedDllCoverage(std::set<ULONGLONG>& _addresses, peconv::ExportsMapper& _exportsMap)
            : addresses(_addresses), exportsMap(_exportsMap)
        {
        }

        // Checks if all the addresses can be covered by one DLL. If yes, this dll will be saved into: dllName.
        bool findCoveringDll();

        // Map the addresses to functions from the given DLL. Return true if all functions are covered. Results are saved into: addrToFunc.
        // before each execution, the content of addrToFunc is erased
        bool mapAddressesToFunctions(std::string dll);

        std::map<ULONGLONG, std::set<ExportedFunc>> addrToFunc;
        std::string dllName;

    protected:
        std::set<ULONGLONG> &addresses;
        peconv::ExportsMapper& exportsMap;
    };
}
