#pragma once

#include <Windows.h>

#include <string>

#include <set>
#include <map>

#include <iterator>
#include "fix_imports.h"
#include "caves.h"

namespace peconv {
    class ImportsUneraser
    {
    public:
        ImportsUneraser(PVOID _modulePtr, size_t _moduleSize)
            : modulePtr((PBYTE)_modulePtr), moduleSize(_moduleSize)
        {
            is64 = peconv::is64bit((BYTE*)modulePtr);
        }

        bool uneraseDllImports(IMAGE_IMPORT_DESCRIPTOR* lib_desc, ImportedDllCoverage &dllCoverage);
        bool uneraseDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, ImportedDllCoverage &dllCoverage);

    protected:

        bool writeFoundDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, std::string found_name);

        template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
        bool fillImportNames(IMAGE_IMPORT_DESCRIPTOR* lib_desc,
                     const FIELD_T ordinal_flag,
                     std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func);


        template <typename FIELD_T>
        bool findNameInBinaryAndFill(IMAGE_IMPORT_DESCRIPTOR* lib_desc,
            LPVOID call_via_ptr,
            LPVOID thunk_ptr,
            const FIELD_T ordinal_flag,
            std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func
        );

        template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
        bool writeFoundFunction(IMAGE_THUNK_DATA_T* desc, const FIELD_T ordinal_flag, const ExportedFunc &foundFunc);

        PBYTE modulePtr;
        size_t moduleSize;
        bool is64;
    };
}
