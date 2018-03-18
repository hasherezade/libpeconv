#pragma once

#include <Windows.h>

#include <string>

#include <set>
#include <map>

#include <iterator>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"
#include "exports_mapper.h"

namespace peconv {

    class ImportedDllCoverage
    {
    public:
        ImportedDllCoverage(std::set<ULONGLONG>& _addresses, peconv::ExportsMapper& _exportsMap)
            : addresses(_addresses), exportsMap(_exportsMap)
        {
        }

        bool findCoveringDll();

        bool mapAddressesToFunctions();
        bool mapAddressesToFunctions(std::string dll);

        std::map<ULONGLONG, std::set<ExportedFunc>> addrToFunc;
        std::string dllName;

    protected:
        std::set<ULONGLONG> &addresses;
        peconv::ExportsMapper& exportsMap;
    };
    
    class ImportsUneraser
    {
    public:
        ImportsUneraser(PVOID _modulePtr, size_t _moduleSize)
            : modulePtr(_modulePtr), moduleSize(_moduleSize)
        {
            is64 = peconv::is64bit((BYTE*)modulePtr);
        }

        bool uneraseDllImports(IMAGE_IMPORT_DESCRIPTOR* lib_desc, ImportedDllCoverage &coveredDll);
        bool uneraseDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc,  ImportedDllCoverage &dllCoverage);

    protected:
        PVOID modulePtr;
        size_t moduleSize;
        bool is64;
    };

    bool fix_imports(PVOID modulePtr, size_t moduleSize, peconv::ExportsMapper& exportsMap);
}
