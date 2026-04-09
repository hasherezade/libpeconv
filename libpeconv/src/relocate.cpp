#include "peconv/relocate.h"

#include "peconv/pe_hdrs_helper.h"
#include <stdio.h>
#include "peconv/logger.h"

using namespace peconv;

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

class ApplyRelocCallback : public RelocBlockCallback
{
public:
    ApplyRelocCallback(bool _is64bit, ULONGLONG _oldBase, ULONGLONG _newBase)
        : RelocBlockCallback(_is64bit), oldBase(_oldBase), newBase(_newBase)
    {
    }

    virtual bool processRelocField(ULONG_PTR relocField)
    {
        if (is64bit) {
            ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)relocField);
            ULONGLONG rva = (*relocateAddr) - oldBase;
            (*relocateAddr) = rva + newBase;
        }
        else {
            DWORD* relocateAddr = (DWORD*)((ULONG_PTR)relocField);
            ULONGLONG rva = ULONGLONG(*relocateAddr) - oldBase;
            (*relocateAddr) = static_cast<DWORD>(rva + newBase);
        }
        return true;
    }

protected:
    ULONGLONG oldBase;
    ULONGLONG newBase;
};

bool is_empty_reloc_block(BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, PVOID modulePtr, SIZE_T moduleSize)
{
    if (entriesNum == 0) {
        return true; // nothing to process
    }
    BASE_RELOCATION_ENTRY* entry = block;
    for (SIZE_T i = 0; i < entriesNum; i++) {
        if (!validate_ptr(modulePtr, moduleSize, entry, sizeof(BASE_RELOCATION_ENTRY))) {
            return false;
        }
        DWORD type = entry->Type;
        if (type != 0) {
            //non empty block found
            return false;
        }
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
    }
    return true;
}

namespace {
    bool validate_reloc_field(PVOID modulePtr, SIZE_T moduleSize, bool is64bit, const DWORD reloc_field)
    {
        const size_t field_width = is64bit ? sizeof(ULONGLONG) : sizeof(DWORD);
        const ULONG_PTR reloc_ptr = (ULONG_PTR)modulePtr + reloc_field;
        return peconv::validate_ptr(modulePtr, moduleSize, (LPVOID)reloc_ptr, field_width);
    }
};

bool process_reloc_block(BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, PVOID modulePtr, SIZE_T moduleSize, bool is64bit, RelocBlockCallback *callback)
{
    if (entriesNum == 0) {
        return true; // nothing to process
    }
    BASE_RELOCATION_ENTRY* entry = block;
    SIZE_T i = 0;
    for (i = 0; i < entriesNum; i++) {
        if (!validate_ptr(modulePtr, moduleSize, entry, sizeof(BASE_RELOCATION_ENTRY))) {
            break;
        }
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        if (type == 0) {
            entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
            continue;  // skip padding
        }
        if (type != RELOC_32BIT_FIELD && type != RELOC_64BIT_FIELD) {
            if (callback) { //print debug messages only if the callback function was set
                LOG_ERROR("Not supported relocation format at %d: %d.", (int)i, (int)type);
            }
            return false;
        }
        const DWORD reloc_field = page + offset;
        if (!validate_reloc_field(modulePtr, moduleSize, is64bit, reloc_field)) {
            if (callback) { //print debug messages only if the callback function was set
                LOG_ERROR("Malformed reloc field: 0x%lx.", reloc_field);
            }
            return false;
        }
        if (callback) {
            bool isOk = callback->processRelocField(((ULONG_PTR)modulePtr + reloc_field));
            if (!isOk) {
                LOG_ERROR("Failed processing reloc field at: 0x%lx.", reloc_field);
                return false;
            }
        }
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
    }
    return (i != 0);
}

bool peconv::process_relocation_table(IN PVOID modulePtr, IN SIZE_T moduleSize, IN RelocBlockCallback *callback)
{
    IMAGE_DATA_DIRECTORY* relocDir = peconv::get_directory_entry((const BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
        LOG_DEBUG("No relocation table found.");
        return false;
    }
    if (!validate_ptr(modulePtr, moduleSize, relocDir, sizeof(IMAGE_DATA_DIRECTORY))) {
        LOG_ERROR("Invalid relocDir pointer.");
        return false;
    }
    const DWORD maxSize = relocDir->Size;
    const DWORD relocAddr = relocDir->VirtualAddress;
    const bool is64b = is64bit((BYTE*)modulePtr);

    IMAGE_BASE_RELOCATION* reloc = NULL;

    DWORD parsedSize = 0;
    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR)modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, reloc, sizeof(IMAGE_BASE_RELOCATION))) {
            LOG_ERROR("Invalid address of relocations.");
            return false;
        }
        if (reloc->SizeOfBlock < (2 * sizeof(DWORD))) {
            LOG_ERROR("Malformed relocation block: SizeOfBlock too small.");
            return false;
        }
        const size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
        const DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
        if (!validate_ptr(modulePtr, moduleSize, block, sizeof(BASE_RELOCATION_ENTRY))) {
            LOG_ERROR("Invalid address of relocations block.");
            return false;
        }
        if (!is_empty_reloc_block(block, entriesNum, page, modulePtr, moduleSize)) {
            if (!process_reloc_block(block, entriesNum, page, modulePtr, moduleSize, is64b, callback)) {
                // the block was malformed
                return false;
            }
        }
        const DWORD _newParsedSize = parsedSize + reloc->SizeOfBlock;
        if (_newParsedSize < parsedSize) {
            LOG_ERROR("Invalid SizeOfBlock: DWORD overflow.");
            return false;
        }
        parsedSize = _newParsedSize;
    }
    return true;
}

bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
{
    const bool is64b = is64bit((BYTE*)modulePtr);
    ApplyRelocCallback callback(is64b, oldBase, newBase);
    return process_relocation_table(modulePtr, moduleSize, &callback);
}

bool peconv::relocate_module(IN PBYTE modulePtr, IN SIZE_T moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase)
{
    if (!modulePtr || !moduleSize) {
        return false;
    }
    if (oldBase == 0) {
        oldBase = get_image_base(modulePtr);
    }
    LOG_DEBUG("New Base: 0x%llx Old Base: 0x%llx.", (unsigned long long)newBase, (unsigned long long)oldBase);
    if (newBase == oldBase) {
        LOG_DEBUG("Nothing to relocate: oldBase equals newBase.");
        return true; //nothing to relocate
    }
    if (apply_relocations(modulePtr, moduleSize, newBase, oldBase)) {
        return true;
    }
    LOG_ERROR("Could not relocate the module.");
    return false;
}

bool peconv::has_valid_relocation_table(IN const PBYTE modulePtr, IN const size_t moduleSize)
{
    return process_relocation_table(modulePtr, moduleSize, nullptr);
}

namespace {
    bool virtual_addr_to_rva_no_relocs(IN const BYTE* modulePtr, IN const DWORD module_size, IN ULONGLONG callback_addr, OUT DWORD& callback_rva)
    {
        const ULONGLONG img_base = (ULONGLONG)modulePtr;
        //check if VA:
        if (callback_addr >= img_base && callback_addr < (img_base + module_size)) {
            callback_rva = MASK_TO_DWORD(callback_addr - img_base);
            return true;
        }
        if (callback_addr < module_size) {
            callback_rva = MASK_TO_DWORD(callback_addr);
            return true;
        }
        // out of scope address
        return false;
    }
}

bool peconv::virtual_addr_to_rva(IN const PBYTE modulePtr, IN const size_t module_size, IN ULONGLONG callback_addr, OUT DWORD& callback_rva, IN std::unordered_set<ULONGLONG>* _relocs)
{
    if (!module_size || !callback_addr) return false;

    const ULONGLONG img_base = (ULONGLONG)modulePtr;

    std::unordered_set<ULONGLONG> local_relocs;
    std::unordered_set<ULONGLONG>& reloc_values = _relocs ? (*_relocs) : local_relocs;
    if (!_relocs && peconv::has_relocations(modulePtr)) {
        // Collect relocations for VA detection
        CollectRelocs callback(modulePtr, module_size, peconv::is64bit(modulePtr), reloc_values);
        process_relocation_table(modulePtr, module_size, &callback);
    }
    
    // for files with no relocation table use simple heuristics:
    if (reloc_values.empty()) {
        return virtual_addr_to_rva_no_relocs(modulePtr, module_size, callback_addr, callback_rva);
    }
    // Helper to convert VA -> RVA if the address is in relocation table
    auto _convert_va_to_rva = [&](ULONGLONG& addr, DWORD &rva) -> bool
        {
            if (reloc_values.find(addr) != reloc_values.end()) {
                // found: input is a VA
                if (addr < img_base) {
                    LOG_ERROR("Invalid VA: 0x%llx cannot convert safely", addr);
                    return false;
                }
                rva = addr - img_base;
            }
            else {
                // not found: input is a RVA
                if (addr > module_size) {
                    return false;
                }
                rva = static_cast<DWORD>(addr);
            }
            return true;
        };
    return _convert_va_to_rva(callback_addr, callback_rva);
}

