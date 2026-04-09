/**
* @file
* @brief   Operating on PE file's relocations table.
*/

#pragma once
#include <windows.h>
#include <unordered_set>

#include "peconv/buffer_util.h"

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

        virtual ~RelocBlockCallback() {}

        virtual bool processRelocField(ULONG_PTR relocField) = 0;

    protected:
        bool is64bit;
    };

    //--

    class CollectRelocs : public peconv::RelocBlockCallback
    {
    public:
        CollectRelocs(const BYTE* pe_buffer, size_t buffer_size, IN bool _is64bit, OUT std::unordered_set<ULONGLONG>& _relocs)
            : RelocBlockCallback(_is64bit), relocs(_relocs),
            peBuffer(pe_buffer), bufferSize(buffer_size)
        {
        }

        virtual bool processRelocField(ULONG_PTR relocField)
        {
            ULONGLONG rva = 0;
            if (is64bit) {
                
                ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)relocField);
                if (!validate_ptr(peBuffer, bufferSize, relocateAddr, sizeof(ULONGLONG))) {
                    return false;
                }
                rva = (*relocateAddr);
            }
            else {
                DWORD* relocateAddr = (DWORD*)((ULONG_PTR)relocField);
                if (!validate_ptr(peBuffer, bufferSize, relocateAddr, sizeof(DWORD))) {
                    return false;
                }
                rva = ULONGLONG(*relocateAddr);
            }
            relocs.insert(rva);
            return true;
        }

    protected:
        std::unordered_set<ULONGLONG>& relocs;

        const BYTE* peBuffer;
        size_t bufferSize;
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
    bool relocate_module(IN PBYTE modulePtr, IN SIZE_T moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase = 0);

    /**
    Checks if the given  PE has a valid relocations table.
    \param modulePtr : a buffer containing the PE to be checked
    \param moduleSize : the size of the given PE buffer
    */
    bool has_valid_relocation_table(IN const PBYTE modulePtr, IN const size_t moduleSize);

    /**
    A helper function, normalizing virtual addresses. It automatically detects if the given virtual address is VA or RVA, and converts it into RVA.
    Works only for virtual, relocated modules.
    \param imgBase : pointer to the module buffer, indicating the base address to which it was relocated
    \param imgSize : the size of the image
    \param virtualAddr : the virtual address (RVA or VA) that we want to convert (within the module described by imgBase and imgSize)
    \param outRVA : the output of the conversion (RVA)
    \param relocs : cached list of relocations (optional). If nullptr is passed, the function will try to collect the set internally (if reloc table exists).
    \return true if the conversion was successful, false otherwise
    */
    bool virtual_addr_to_rva(IN const PBYTE imgBase, IN const DWORD imgSize, IN ULONGLONG virtualAddr, OUT DWORD& outRVA, IN std::unordered_set<ULONGLONG>* relocs=nullptr);

};//namespace peconv
