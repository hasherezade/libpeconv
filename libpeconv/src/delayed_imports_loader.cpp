#include "peconv/delayed_imports_loader.h"
#include "peconv/imports_loader.h"

#include <iostream>

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

template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
bool parse_delayed_desc(BYTE* modulePtr, const size_t moduleSize, 
    const ULONGLONG img_base, 
    LPSTR lib_name, 
    const T_FIELD ordinal_flag, 
    IMAGE_DELAYLOAD_DESCRIPTOR *desc, 
    peconv::t_function_resolver* func_resolver
)
{
    ULONGLONG iat_addr = desc->ImportAddressTableRVA;
    
    if (iat_addr > img_base) iat_addr -= img_base; // it may be either RVA or VA

    ULONGLONG thunk_addr = desc->ImportNameTableRVA;
    if (thunk_addr > img_base) thunk_addr -= img_base; // it may be either RVA or VA

    T_FIELD* record_va = (T_FIELD*)((ULONGLONG)modulePtr + iat_addr);
    T_IMAGE_THUNK_DATA* thunk_va = (T_IMAGE_THUNK_DATA*)((ULONGLONG)modulePtr + thunk_addr);

    for (; *record_va != NULL && thunk_va != NULL; record_va++, thunk_va++) {
        if (!peconv::validate_ptr(modulePtr, moduleSize, record_va, sizeof(T_FIELD))) {
            return false;
        }
        if (!peconv::validate_ptr(modulePtr, moduleSize, thunk_va, sizeof(T_FIELD))) {
            return false;
        }

        T_FIELD iat_va = *record_va;
        ULONGLONG iat_rva = (ULONGLONG)iat_va;
        if (iat_va > img_base) iat_rva -= img_base; // it may be either RVA or VA
#ifdef _DEBUG
        std::cout << std::hex << iat_rva << " : ";
#endif
        T_FIELD* iat_record_ptr = (T_FIELD*)((ULONGLONG)modulePtr + iat_rva);
        if (!peconv::validate_ptr(modulePtr, moduleSize, iat_record_ptr, sizeof(T_FIELD))) {
            return false;
        }
        FARPROC hProc = nullptr;
        if (thunk_va->u1.Ordinal & ordinal_flag) {
            T_FIELD raw_ordinal = thunk_va->u1.Ordinal & (~ordinal_flag);
#ifdef _DEBUG
            std::cout << std::hex << "ord: " << raw_ordinal << " ";
#endif
            hProc = func_resolver->resolve_func(lib_name, MAKEINTRESOURCEA(raw_ordinal));
        }
        else {
            ULONGLONG name_rva = thunk_va->u1.AddressOfData;
            if (name_rva > img_base) {
                name_rva -= img_base;
            }
            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + name_rva);
            LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
            if (!peconv::is_valid_import_name(modulePtr, moduleSize, func_name)) {
                continue;
            }
#ifdef _DEBUG
            std::cout << func_name << " ";
#endif
            hProc = func_resolver->resolve_func(lib_name, func_name);
        }
        if (hProc) {
            //rather than loading it via proxy function, we just overwrite the thunk like normal IAT:
            *record_va = (T_FIELD) hProc;
#ifdef _DEBUG
            std::cout << "[OK]\n";
#endif
        }
        else {
#ifdef _DEBUG
            std::cout << "[NOPE]\n";
#endif
        }
    }
    return true;
}

bool peconv::load_delayed_imports(BYTE* modulePtr, ULONGLONG moduleBase, t_function_resolver* func_resolver)
{
    const bool is_64bit = peconv::is64bit(modulePtr);
    bool is_loader64 = false;
#ifdef _WIN64
    is_loader64 = true;
#endif
    if (is_64bit != is_loader64) {
        std::cerr << "[ERROR] Loader/Payload bitness mismatch.\n";
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
#ifdef _DEBUG
    std::cout << "OK, table_size = " << table_size << std::endl;
#endif
    size_t max_count = table_size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
    for (size_t i = 0; i < max_count; i++) {
        IMAGE_DELAYLOAD_DESCRIPTOR *desc = &first_desc[i];
        if (!validate_ptr(modulePtr, module_size, desc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) break;
        if (desc->DllNameRVA == NULL) {
            break;
        }
        ULONGLONG dll_name_rva = desc->DllNameRVA;
        if (dll_name_rva > moduleBase) {
            dll_name_rva -= moduleBase;
        }
        char* dll_name = (char*)((ULONGLONG) modulePtr + dll_name_rva);
        if (!validate_ptr(modulePtr, module_size, dll_name, sizeof(char))) continue;
#ifdef _DEBUG
        std::cout << dll_name << std::endl;
#endif
        if (is_64bit) {
#ifdef _WIN64
            parse_delayed_desc<ULONGLONG,IMAGE_THUNK_DATA64>(modulePtr, module_size, moduleBase, dll_name, IMAGE_ORDINAL_FLAG64, desc, func_resolver);
#else
            return false;
#endif
        }
        else {
#ifndef _WIN64
            parse_delayed_desc<DWORD, IMAGE_THUNK_DATA32>(modulePtr, module_size, moduleBase, dll_name, IMAGE_ORDINAL_FLAG32, desc, func_resolver);
#else
            return false;
#endif
        }
    }
    return true;
}
