/**
* @file
* @brief   Parsing and filling the Import Table.
*/

#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"

namespace peconv {

    /**
    A callback that will be executed by process_import_table when the next imported function was found
    */
    class ImportThunksCallback
    {
    public:
        ImportThunksCallback(BYTE* _modulePtr, size_t _moduleSize)
            : modulePtr(_modulePtr), moduleSize(_moduleSize)
        {
            this->is64b = is64bit((BYTE*)modulePtr);
        }

        virtual bool processThunks(LPSTR lib_name, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) = 0;

    protected:
        BYTE* modulePtr;
        size_t moduleSize;
        bool is64b;
    };


    /**
    Process the given PE's import table and execute the callback each time when the new imported function was found
    */
    bool process_import_table(IN BYTE* modulePtr, IN SIZE_T moduleSize, IN ImportThunksCallback *callback);

    /**
    Fills imports of the given PE with the help of the defined functions resolver.
    */
    bool load_imports(BYTE* modulePtr, t_function_resolver* func_resolver=nullptr);

    /**
    Checks if the given PE has a valid import table.
    */
    bool has_valid_import_table(const PBYTE modulePtr, size_t moduleSize);

    /**
    Checks if the given lib_name is a valid DLL name.
    A valid name must contain printable characters. Empty name is also acceptable (may have been erased).
    */
    bool is_valid_import_name(const PBYTE modulePtr, const size_t moduleSize, LPSTR lib_name);

}; // namespace peconv
