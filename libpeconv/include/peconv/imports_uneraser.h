/**
* @file
* @brief   A definition of ImportsUneraser class - for recovery of a partialy erased Import Table.
*/

#pragma once

#include <windows.h>

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
        Fill the imported functions' names in the given Import Descriptor, using the given coverage.
        Collect addressees of functions that couldn't be filled with the given mapping.
        \param lib_desc : the IMAGE_IMPORT_DESCRIPTOR where the functions' names should be set
        \param dllCoverage : a mapping associating addresses with the corresponding exports from available DLLs
        \param not_covered : a set of addresses that could not be found in the supplied mapping
        \return true if succeeded
        */
        bool uneraseDllImports(IN OUT IMAGE_IMPORT_DESCRIPTOR* lib_desc, IN ImportedDllCoverage &dllCoverage, OUT OPTIONAL ImpsNotCovered* not_covered);

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

        /**
        Fill the names of imported functions with names of the prepared mapping.
        Collect addressees of functions that couldn't be filled with the given mapping.
        \param lib_desc : the IMAGE_IMPORT_DESCRIPTOR where the functions' names should be set
        \param ordinal_flag : the flag that is used to recognize import by ordinal (32 or 64 bit)
        \param addr_to_func : a mapping assigning functions' addresses to their definitions (names etc.)
        \param not_covered : a set of addresses that could not be found in the supplied mapping
        \return true if succeeded
        */
        template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
        bool fillImportNames(IN OUT IMAGE_IMPORT_DESCRIPTOR* lib_desc,
                IN const FIELD_T ordinal_flag,
                IN std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func,
                OUT OPTIONAL ImpsNotCovered* not_covered
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
