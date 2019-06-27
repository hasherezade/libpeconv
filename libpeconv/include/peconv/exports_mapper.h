#pragma once

#include <Windows.h>

#include <string>
#include <map>
#include <set>

#include "pe_hdrs_helper.h"
#include "pe_raw_to_virtual.h"
#include "peconv/exported_func.h"
#include "peconv/file_util.h"

namespace peconv {

    class ExportsMapper {

    public:

        /**
        Appends the given DLL to the lookup table of exported functions. Returns the number of functions exported from this DLL (not forwarded).
        \param moduleName : name of the DLL
        \param modulePtr : buffer containing the DLL in a Virtual format
        \param moduleBase : a base address to which the given DLL was relocated
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr, ULONGLONG moduleBase);

        /**
        Appends the given DLL to the lookup table of exported functions. Returns the number of functions exported from this DLL (not forwarded).
        Assumes that the module was relocated to the same address as is the address of the given buffer (modulePtr).
        (A wrapper fot the case if we are adding a DLL that was loaded within the current process.)
        \param moduleName : name of the DLL
        \param modulePtr : buffer containing the DLL in a Virtual format. 
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr) 
        {
            return add_to_lookup(moduleName, modulePtr, reinterpret_cast<ULONGLONG>(modulePtr));
        }

        /**
        Find the set of Exported Functions that can be mapped to the given VA. Includes forwarders, and function aliases.
        */
        const std::set<ExportedFunc>* find_exports_by_va(ULONGLONG va) const
        {
            std::map<ULONGLONG, std::set<ExportedFunc>>::const_iterator itr = va_to_func.find(va);
            if (itr != va_to_func.end()) {
                const std::set<ExportedFunc> &fSet = itr->second;
                return &fSet;
            }
            return NULL;
        }

        /**
        Retrieve the full path of the DLL with the given short name.
        */
        std::string get_dll_path(std::string short_name) const
        {
            std::map<std::string, std::string>::const_iterator found = this->dll_shortname_to_path.find(short_name);
            if (found == dll_shortname_to_path.end()) {
                return "";
            }
            return found->second;
        }

        /**
        Retrieve the full name of the DLL (including the extension) using its short name (without the extension).
        */
        std::string get_dll_fullname(std::string short_name) const
        {
            std::string dll_path = get_dll_path(short_name);
            if (dll_path.length() == 0) return "";

            return get_file_name(dll_path);
        }

        /**
        Find an Exported Function that can be mapped to the given VA,
        */
        const ExportedFunc* find_export_by_va(ULONGLONG va) const
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
        size_t make_ord_lookup_tables(PVOID modulePtr, size_t moduleSize, std::map<PDWORD, DWORD> &va_to_ord);

    protected:
        std::map<ULONGLONG, std::set<ExportedFunc>> va_to_func;
        std::map<ExportedFunc, std::set<ExportedFunc>> forwarders_lookup;
        std::map<ExportedFunc, ULONGLONG> func_to_va;
        std::map<std::string, std::string> dll_shortname_to_path;
    };

}; //namespace peconv
