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

        // Appends the given DLL to the lookup table of exported functions. Returns the number of functions exported from this DLL (not forwarded).
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr, ULONGLONG moduleBase);

        // wrapper (for current process) - if the modulePtr is same as the module base
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr) 
        {
            return add_to_lookup(moduleName, modulePtr, reinterpret_cast<ULONGLONG>(modulePtr));
        }

        //which DLL exports the function of given address?
        const std::set<ExportedFunc>* find_exports_by_va(ULONGLONG va)
        {
            std::map<ULONGLONG, std::set<ExportedFunc>>::iterator itr = va_to_func.find(va);
            if (itr != va_to_func.end()) {
                std::set<ExportedFunc> &fSet = itr->second;
                return &fSet;
            }
            return NULL;
        }

        //which DLL exports the function of given address? give the first entry
        const ExportedFunc* find_export_by_va(ULONGLONG va)
        {
            const std::set<ExportedFunc>* exp_set = find_exports_by_va(va);
            if (exp_set == NULL) return NULL;

            std::set<ExportedFunc>::iterator fItr = exp_set->begin();
            const ExportedFunc* func = &(*fItr);
            return func;
        }

    private:
        bool add_forwarded(PBYTE fPtr, ExportedFunc &currFunc);
        bool add_to_maps(ULONGLONG va, ExportedFunc &currFunc);

        size_t resolve_forwarders(const ULONGLONG va, ExportedFunc &currFunc);
        size_t make_ord_lookup_tables(PVOID modulePtr, std::map<ULONGLONG, DWORD> &va_to_ord);

    protected:
        std::map<ULONGLONG, std::set<ExportedFunc>> va_to_func;
        std::map<ExportedFunc, std::set<ExportedFunc>> forwarders_lookup;
        std::map<ExportedFunc, ULONGLONG> func_to_va;
    };

}; //namespace peconv
