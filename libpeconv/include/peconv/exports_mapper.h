/**
* @file
* @brief   A definition of ExportsMapper class. Creates a lookup of all the exported functions from the supplied DLLs. Allows to associate an address with a corresponding function.
*/

#pragma once

#include <windows.h>

#include <string>
#include <map>
#include <set>
#include <sstream>

#include "pe_hdrs_helper.h"
#include "pe_raw_to_virtual.h"
#include "peconv/exported_func.h"
#include "peconv/file_util.h"

namespace peconv {

    struct DllInfo {
        DllInfo()
            : moduleBase(0), moduelSize(0), is64b(false)
        {
        }

        DllInfo(ULONGLONG _moduleBase, size_t _moduelSize, bool _is64b, std::string _moduleName)
        {
            moduleBase = _moduleBase;
            moduelSize = _moduelSize;
            moduleName = _moduleName;
            is64b = _is64b;
            shortName = get_dll_shortname(moduleName);
        }

        DllInfo(const DllInfo &other)
        {
            moduleBase = other.moduleBase;
            moduelSize = other.moduelSize;
            moduleName = other.moduleName;
            shortName = other.shortName;
            is64b = other.is64b;
        }

        bool operator<(const DllInfo &other) const
        {
            return this->moduleBase < other.moduleBase;
        }

    protected:
        ULONGLONG moduleBase;
        size_t moduelSize;
        std::string moduleName;
        std::string shortName;
        bool is64b;

        friend class ExportsMapper;
    };

    class ExportsMapper {

    public:

        /**
        Appends the given DLL to the lookup table of exported functions. Returns the number of functions exported from this DLL (not forwarded).
        \param moduleName : name of the DLL
        \param modulePtr : buffer containing the DLL in a Virtual format
        \param moduleSize : size of the DLL buffer. If moduleSize == 0, the ImageSize from the PE headers will be used.
        \param moduleBase : a base address to which the given DLL was relocated
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr, size_t moduleSize, ULONGLONG moduleBase);

        /**
        Appends the given DLL to the lookup table of exported functions. Returns the number of functions exported from this DLL (not forwarded).
        \param moduleName : name of the DLL
        \param modulePtr : buffer containing the DLL in a Virtual format
        \param moduleBase : a base address to which the given DLL was relocated
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr, ULONGLONG moduleBase)
        {
            return add_to_lookup(moduleName, modulePtr, 0, moduleBase);
        }

        /**
        Appends the given DLL to the lookup table of exported functions. Returns the number of functions exported from this DLL (not forwarded).
        Assumes that the module was relocated to the same address as is the address of the given buffer (modulePtr).
        (A wrapper for the case if we are adding a DLL that was loaded within the current process.)
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
        Retrieve the base of the DLL containing the given function. If not found, returns 0.
        */
        ULONGLONG find_dll_base_by_func_va(ULONGLONG func_rva) const
        {
            // the first element that is greater than the start address
            std::map<ULONGLONG, DllInfo>::const_iterator firstGreater = dll_base_to_info.upper_bound(func_rva);

            std::map<ULONGLONG, DllInfo>::const_iterator itr;
            for (itr = dll_base_to_info.begin(); itr != firstGreater; ++itr) {
                const DllInfo& module = itr->second;

                if (func_rva >= module.moduleBase && func_rva <= (module.moduleBase + module.moduelSize)) {
                    // Address found in module:
                    return module.moduleBase;
                }
            }
            return 0;
        }

        /**
        Retrieve the full path of the DLL with the given module base.
        */
        std::string get_dll_path(ULONGLONG base) const
        {
            std::map<ULONGLONG, DllInfo>::const_iterator found =  this->dll_base_to_info.find(base);
            if (found == this->dll_base_to_info.end()) { // no DLL found at this base
                return "";
            }
            const DllInfo& info = found->second;
            return info.moduleName;
        }

        /**
        Retrieve the path of the DLL with the given short name. If multiple paths are mapped to the same short name, it retrieves the first one.
        */
        std::string get_dll_path(std::string short_name) const;

        /**
        Retrieve the paths of the DLL with the given short name.
        */
        size_t get_dll_paths(IN std::string short_name, OUT std::set<std::string>& paths) const;

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

        void print_va_to_func(std::stringstream &stream) const;
        void print_func_to_va(std::stringstream &stream) const;
        

    private:
        enum ADD_FUNC_RES { RES_INVALID = 0, RES_MAPPED = 1, RES_FORWARDED = 2 };
        ADD_FUNC_RES add_function_to_lookup(HMODULE modulePtr, ULONGLONG moduleBase, size_t moduleSize, ExportedFunc &currFunc, DWORD callRVA);

        bool add_forwarded(ExportedFunc &currFunc, DWORD callRVA, PBYTE modulePtr, size_t moduleSize);
        bool add_to_maps(ULONGLONG va, ExportedFunc &currFunc);

        size_t resolve_forwarders(const ULONGLONG va, ExportedFunc &currFunc);
        size_t make_ord_lookup_tables(PVOID modulePtr, size_t moduleSize, std::map<PDWORD, DWORD> &va_to_ord);

    protected:
        /**
        Add a function and a VA into a mutual mapping.
        */
        void associateVaAndFunc(ULONGLONG va, const ExportedFunc& func)
        {
            va_to_func[va].insert(func);
            func_to_va[func] = va;
        }

        /**
        A map associating VA of the function with the related exports.
        */
        std::map<ULONGLONG, std::set<ExportedFunc>> va_to_func;

        /**
        A map associating an exported functions with its forwarders.
        */
        std::map<ExportedFunc, std::set<ExportedFunc>> forwarders_lookup;

        /**
        A map associating an exported functions with its VA.
        */
        std::map<ExportedFunc, ULONGLONG> func_to_va;
        
        /**
        A map associating DLL shortname with the base(s) at which it was mapped
        */
        std::map<std::string, std::set<ULONGLONG>> dll_shortname_to_base;

        std::map<ULONGLONG, DllInfo> dll_base_to_info;
    };

}; //namespace peconv
