/**
* @file
* @brief   Operating on PE file's relocations table.
*/

#pragma once

#include <windows.h>

namespace peconv {

    typedef struct _BASE_RELOCATION_ENTRY {
        WORD Offset : 12;
        WORD Type : 4;
    } BASE_RELOCATION_ENTRY;

    class RelocBlockCallback
    {
    public:
        RelocBlockCallback(bool _is64bit)
            : is64bit(_is64bit)
        {
        }

        virtual bool processRelocField(ULONG_PTR relocField) = 0;

    protected:
        bool is64bit;
    };

    // Processs the relocation table and make your own callback on each relocation field
    bool process_relocation_table(IN PVOID modulePtr, IN SIZE_T moduleSize, IN RelocBlockCallback *callback);

    /** 
     Applies relocations on the PE in virtual format. Relocates it from the old base given to the new base given.
     If 0 was supplied as the old base, it assumes that the old base is the ImageBase given in the header.
     \param modulePtr : a buffer containing the PE to be relocated
     \param moduleSize : the size of the given PE buffer
     \param newBase : a base to which the PE should be relocated
     \param oldBase : a base to which the PE is currently relocated (if not set, the imageBase from the header will be used)
    */
    bool relocate_module(IN BYTE* modulePtr, IN SIZE_T moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase = 0);

    /**
    Checks if the given  PE has a valid relocations table.
    \param modulePtr : a buffer containing the PE to be checked
    \param moduleSize : the size of the given PE buffer
    */
    bool has_valid_relocation_table(IN const PBYTE modulePtr, IN const size_t moduleSize);

};//namespace peconv
