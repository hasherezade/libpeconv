/**
* @file
* @brief   A definition of ImportsUneraser class - for recovery of a partialy erased Import Table.
*/

#pragma once

#include <Windows.h>

#include <string>

#include <set>
#include <map>

#include <iterator>
#include "fix_imports.h"
#include "caves.h"

namespace peconv {
    /**
    A class responsible for recovering the partially erased Import Table from the PE.
    */
    class ImportsUneraser
    {
    public:
        ImportsUneraser(PVOID _modulePtr, size_t _moduleSize)
            : modulePtr((PBYTE)_modulePtr), moduleSize(_moduleSize)
        {
            is64 = peconv::is64bit((BYTE*)modulePtr);
        }

        /**
        Recover the imported functions' names in the given Import Descriptor, using the given coverage.
        */
        bool uneraseDllImports(IMAGE_IMPORT_DESCRIPTOR* lib_desc, ImportedDllCoverage &dllCoverage, std::set<ULONGLONG> &not_recovered);

        /**
        Recover the imported DLL name in the given Import Descriptor, filling it with the given dll_name.
        */
        bool uneraseDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, const std::string &dll_name);

    protected:
        /**
        Copy the given DLL name into the given IMAGE_IMPORT_DESCRIPTOR. Validates the data correctness before writing.
        \param lib_desc : the IMAGE_IMPORT_DESCRIPTOR where the DLL name should be set
        \param dll_name : the DLL name that needs to be written into the lib_desc
        \return true if succeeded
        */
        bool writeFoundDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, const std::string &dll_name);

        template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
        bool fillImportNames(IN IMAGE_IMPORT_DESCRIPTOR* lib_desc,
                IN const FIELD_T ordinal_flag,
                OUT std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func,
                OUT std::set<ULONGLONG> &not_recovered
            );


        template <typename FIELD_T>
        bool findNameInBinaryAndFill(IMAGE_IMPORT_DESCRIPTOR* lib_desc,
            LPVOID call_via_ptr,
            LPVOID thunk_ptr,
            const FIELD_T ordinal_flag,
            std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func
        );

        /**
        Fill the function data into the given IMAGE_THUNK_DATA.
        \param desc : the poiner to IMAGE_THUNK_DATA that will be filled
        \param ordinal_flag : an ordinal flag: 32 or 64 bit
        \param foundFunc : the ExportedFunc that will be used for filling the desc
        */
        template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
        bool writeFoundFunction(IMAGE_THUNK_DATA_T* desc, const FIELD_T ordinal_flag, const ExportedFunc &foundFunc);

        PBYTE modulePtr;
        size_t moduleSize;
        bool is64;
    };
}
