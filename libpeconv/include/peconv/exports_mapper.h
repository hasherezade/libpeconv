#pragma once

#include <Windows.h>

#include <string>
#include <map>
#include <set>

#include "pe_hdrs_helper.h"
#include "pe_raw_to_virtual.h"
#include "peconv/exported_func.h"

namespace peconv {

    class ExportsMapper {

    public:
        size_t addToLookupTables(std::string moduleName, HMODULE modulePtr);

        const ExportedFunc* getFuncAt(ULONGLONG va)
        {
            std::map<ULONGLONG, std::set<ExportedFunc>>::iterator itr = va_to_func.find(va);
            if (itr != va_to_func.end()) {
                std::set<ExportedFunc> &fSet = itr->second;
                std::set<ExportedFunc>::iterator fItr = fSet.begin();
                const ExportedFunc* func = &(*fItr);
                return func;
            }
            return NULL;
        }

    private:
        size_t resolve_forwarders(const ULONGLONG va, ExportedFunc &currFunc);

        size_t make_ord_lookup_tables(PVOID modulePtr, std::map<ULONGLONG, DWORD> &va_to_ord);

    protected:
        std::map<ExportedFunc, std::set<ExportedFunc>> forwarders_lookup;
        std::map<ULONGLONG, std::set<ExportedFunc>> va_to_func;
        std::map<ExportedFunc, ULONGLONG> func_to_va;
    };

}; //namespace peconv