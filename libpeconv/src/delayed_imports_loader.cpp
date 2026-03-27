#include "peconv/delayed_imports_loader.h"
#include "peconv/imports_loader.h"
#include "peconv/relocate.h"
#include "peconv/logger.h"

#include <unordered_set>

IMAGE_DELAYLOAD_DESCRIPTOR* peconv::get_delayed_imps(IN const BYTE* modulePtr, IN const size_t moduleSize, OUT size_t &dir_size)
{
    dir_size = 0;
    IMAGE_DATA_DIRECTORY *d_imps_dir = peconv::get_directory_entry(modulePtr, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (!d_imps_dir) {
        return nullptr;
    }
    BYTE* dimps_table = (BYTE*)((ULONGLONG) modulePtr + d_imps_dir->VirtualAddress);
    const size_t min_size = sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
    if (d_imps_dir->Size < min_size) {
        return nullptr;
    }
    if (!peconv::validate_ptr((LPVOID)modulePtr, moduleSize, dimps_table, min_size)) {
        return nullptr;
    }
    dir_size = d_imps_dir->Size;
    return reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR*> (dimps_table);
}

namespace {

    class CollectRelocs : public peconv::RelocBlockCallback
    {
    public:
        CollectRelocs(BYTE* pe_buffer, size_t buffer_size, IN bool _is64bit, OUT std::unordered_set<ULONGLONG>& _relocs)
            : RelocBlockCallback(_is64bit), relocs(_relocs),
            peBuffer(pe_buffer), bufferSize(buffer_size)
        {
        }

        virtual bool processRelocField(ULONG_PTR relocField)
        {
            ULONGLONG reloc_addr = (relocField - (ULONGLONG)peBuffer);
            ULONGLONG rva = 0;
            if (is64bit) {
                ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)relocField);
                rva = (*relocateAddr);
            }
            else {
                DWORD* relocateAddr = (DWORD*)((ULONG_PTR)relocField);
                rva = ULONGLONG(*relocateAddr);
            }
            relocs.insert(rva);
            return true;
        }

    protected:
        std::unordered_set<ULONGLONG>& relocs;

        BYTE* peBuffer;
        size_t bufferSize;
    };
};

template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
bool parse_delayed_desc(
    BYTE* modulePtr, const size_t moduleSize,
    const ULONGLONG img_base,
    LPSTR lib_name,
    const T_FIELD ordinal_flag,
    IMAGE_DELAYLOAD_DESCRIPTOR* desc,
    peconv::t_function_resolver* func_resolver,
    const std::unordered_set<ULONGLONG> &reloc_values
)
{
    if (!peconv::validate_ptr(modulePtr, moduleSize, desc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
        LOG_ERROR("Invalid IMAGE_DELAYLOAD_DESCRIPTOR");
        return false;
    }

    // Helper to convert VA -> RVA if the address is in relocation table
    auto convert_va_to_rva = [&](ULONGLONG& addr) -> bool {
        if (reloc_values.find(addr) != reloc_values.end()) {
            if (addr < img_base) {
                LOG_ERROR("Invalid VA: 0x%llx cannot convert safely", addr);
                return false;
            }
            addr -= img_base;
        }
        return true;
    };

    ULONGLONG iat_addr = desc->ImportAddressTableRVA; // may be VA or RVA
    ULONGLONG thunk_addr = desc->ImportNameTableRVA;  // may be VA or RVA

    if (!convert_va_to_rva(iat_addr) || !convert_va_to_rva(thunk_addr)) {
        return false;
    }

    if (iat_addr > moduleSize || thunk_addr > moduleSize) {
        return false;
    }

    LOG_INFO("iat_addr: 0x%llx, thunk_addr: 0x%llx", iat_addr, thunk_addr);

    T_FIELD* record_va = (T_FIELD*)((ULONGLONG)modulePtr + iat_addr);
    T_IMAGE_THUNK_DATA* thunk_va = (T_IMAGE_THUNK_DATA*)((ULONGLONG)modulePtr + thunk_addr);

    for (; ; record_va++, thunk_va++) {
        if (!peconv::validate_ptr(modulePtr, moduleSize, record_va, sizeof(T_FIELD)) ||
            !peconv::validate_ptr(modulePtr, moduleSize, thunk_va, sizeof(T_IMAGE_THUNK_DATA))) {
            return false;
        }

        if (*record_va == 0) break; // end of table

        ULONGLONG iat_rva = static_cast<ULONGLONG>(*record_va); // may be VA
        if (!convert_va_to_rva(iat_rva)) return false;

        LOG_DEBUG("IAT VA: 0x%llx RVA: 0x%llx", static_cast<unsigned long long>(*record_va), static_cast<unsigned long long>(iat_rva));

        const T_FIELD* iat_record_ptr = (T_FIELD*)((ULONGLONG)modulePtr + iat_rva);
        if (!peconv::validate_ptr(modulePtr, moduleSize, iat_record_ptr, sizeof(T_FIELD))) {
            return false;
        }

        FARPROC hProc = nullptr;
        if (thunk_va->u1.Ordinal & ordinal_flag) {
            T_FIELD raw_ordinal = thunk_va->u1.Ordinal & (~ordinal_flag);
            LOG_DEBUG("ord: 0x%llx", static_cast<unsigned long long>(raw_ordinal));
            if (func_resolver) {
                hProc = func_resolver->resolve_func(lib_name, MAKEINTRESOURCEA(raw_ordinal));
            }
        }
        else {
            ULONGLONG name_rva = thunk_va->u1.AddressOfData;
            if (!convert_va_to_rva(name_rva)) return false;

            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + name_rva);
            if (!peconv::validate_ptr(modulePtr, moduleSize, by_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
                LOG_ERROR("Invalid pointer to IMAGE_IMPORT_BY_NAME");
                return false;
            }

            LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
            if (!peconv::is_valid_import_name(modulePtr, moduleSize, func_name)) {
                continue;
            }

            LOG_DEBUG("func: %s", func_name);
            if (func_resolver) {
                hProc = func_resolver->resolve_func(lib_name, func_name);
            }
        }

        if (hProc) {
            //rather than loading it via proxy function, we just overwrite the thunk like normal IAT:
            *record_va = (T_FIELD) hProc;
            LOG_DEBUG("Delayload Function resolved");
        }
        else {
            LOG_DEBUG("Delayload Function not resolved");
        }
    }

    return true;
}

bool peconv::load_delayed_imports(BYTE* modulePtr, ULONGLONG moduleBase, t_function_resolver* func_resolver)
{
    if (!peconv::get_directory_entry(modulePtr, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)) {
        return true; // nothing to resolve
    }
    const bool is_64bit = peconv::is64bit(modulePtr);
    bool is_loader64 = false;
#ifdef _WIN64
    is_loader64 = true;
#endif
    if (is_64bit != is_loader64) {
        LOG_ERROR("Loader/Payload bitness mismatch.");
        return false;
    }

    const size_t module_size = peconv::get_image_size(modulePtr);
    default_func_resolver default_res;
    if (!func_resolver) {
        func_resolver = (t_function_resolver*)&default_res;
    }
    size_t table_size = 0;
    IMAGE_DELAYLOAD_DESCRIPTOR *first_desc = get_delayed_imps(modulePtr, module_size, table_size);
    if (!first_desc) {
        return false;
    }

    // Collect relocations for VA detection
    std::unordered_set<ULONGLONG> reloc_values;
    CollectRelocs callback(modulePtr, module_size, peconv::is64bit(modulePtr), reloc_values);
    process_relocation_table(modulePtr, module_size, &callback);

    LOG_DEBUG("Delay-import table found, table_size = %zu bytes.", table_size);
    bool is_ok = true;
    size_t max_count = table_size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
    for (size_t i = 0; i < max_count; i++) {
        IMAGE_DELAYLOAD_DESCRIPTOR *desc = &first_desc[i];
        if (!validate_ptr(modulePtr, module_size, desc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) break;
        if (!desc->DllNameRVA) {
            break;
        }
        ULONGLONG dll_name_rva = desc->DllNameRVA;
        if (dll_name_rva > moduleBase) {
            dll_name_rva -= moduleBase;
        }
        char* dll_name = (char*)((ULONGLONG) modulePtr + dll_name_rva);
        if (!validate_ptr(modulePtr, module_size, dll_name, sizeof(char))) continue;
        LOG_DEBUG("Processing delayed imports for: %s", dll_name);
        if (is_64bit) {
#ifdef _WIN64
            is_ok = parse_delayed_desc<ULONGLONG,IMAGE_THUNK_DATA64>(modulePtr, module_size, moduleBase, dll_name, IMAGE_ORDINAL_FLAG64, desc, func_resolver, reloc_values);
#else
            return false;
#endif
        }
        else {
#ifndef _WIN64
            is_ok = parse_delayed_desc<DWORD, IMAGE_THUNK_DATA32>(modulePtr, module_size, moduleBase, dll_name, IMAGE_ORDINAL_FLAG32, desc, func_resolver, reloc_values);
#else
            return false;
#endif
        }
    }
    return is_ok;
}
