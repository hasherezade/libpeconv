#include "peconv/imports_loader.h"

#include <iostream>

using namespace peconv;

class FillImportThunks : public ImportThunksCallback
{
public:
    FillImportThunks(BYTE* _modulePtr, size_t _moduleSize, t_function_resolver* func_resolver)
        : ImportThunksCallback(_modulePtr, _moduleSize), funcResolver(func_resolver)
    {
    }

    virtual bool processThunks(LPSTR lib_name, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr)
    {
        if (this->is64b) {
#ifdef _WIN64 // loader is 64 bit, allow to load imports for 64-bit payload:
            IMAGE_THUNK_DATA64* desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);
            ULONGLONG* call_via = reinterpret_cast<ULONGLONG*>(firstThunkPtr);
            return processThunks_tpl<ULONGLONG, IMAGE_THUNK_DATA64>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG64);
#else
            std::cerr << "[!] Cannot fill imports into 64 bit PE via 32 bit loader!\n";
            return false;
#endif
        }
        else {
#ifndef _WIN64 // loader is 32 bit, allow to load imports for 32-bit payload:
            IMAGE_THUNK_DATA32* desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);
            DWORD* call_via = reinterpret_cast<DWORD*>(firstThunkPtr);
            return processThunks_tpl<DWORD, IMAGE_THUNK_DATA32>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG32);
#else
            std::cerr << "[!] Cannot fill imports into 32 bit PE via 64 bit loader!\n";
            return false;
#endif 
        }
    }

protected:
    template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
    bool processThunks_tpl(LPSTR lib_name, T_IMAGE_THUNK_DATA* desc, T_FIELD* call_via, T_FIELD ordinal_flag)
    {
        if (!this->funcResolver) {
            return false;
        }

        bool is_by_ord = (desc->u1.Ordinal & ordinal_flag) != 0;

        FARPROC hProc = nullptr;
        if (is_by_ord) {
            T_FIELD raw_ordinal = desc->u1.Ordinal & (~ordinal_flag);
#ifdef _DEBUG
            std::cout << "raw ordinal: " << std::hex << raw_ordinal << std::endl;
#endif
            hProc = funcResolver->resolve_func(lib_name, MAKEINTRESOURCEA(raw_ordinal));

        }
        else {
            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
            LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
#ifdef _DEBUG
            std::cout << "name: " << func_name << std::endl;
#endif
            hProc = this->funcResolver->resolve_func(lib_name, func_name);
        }
        if (!hProc) {
#ifdef _DEBUG
            std::cerr << "Could not resolve the function!" << std::endl;
#endif
            return false;
        }
        (*call_via) = reinterpret_cast<T_FIELD>(hProc);
        return true;
    }

    //fields:
    t_function_resolver* funcResolver;
};


template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
bool process_imp_functions_tpl(BYTE* modulePtr, size_t module_size, LPSTR lib_name, DWORD call_via, DWORD thunk_addr, IN ImportThunksCallback *callback)
{
    bool is_ok = true;

    T_FIELD *thunks = (T_FIELD*)((ULONGLONG)modulePtr + thunk_addr);
    T_FIELD *callers = (T_FIELD*)((ULONGLONG)modulePtr + call_via);

    for (size_t index = 0; true; index++) {
        if (!validate_ptr(modulePtr, module_size, &callers[index], sizeof(T_FIELD))) {
            break;
        }
        if (!validate_ptr(modulePtr, module_size, &thunks[index], sizeof(T_FIELD))) {
            break;
        }
        if (callers[index] == 0) {
            //nothing to fill, probably the last record
            return true;
        }
        LPVOID thunk_ptr = &thunks[index];
        T_IMAGE_THUNK_DATA* desc = reinterpret_cast<T_IMAGE_THUNK_DATA*>(thunk_ptr);
        if (!validate_ptr(modulePtr, module_size, desc, sizeof(T_IMAGE_THUNK_DATA))) {
            break;
        }
        if (desc->u1.Function == NULL) {
            break;
        }
        T_FIELD ordinal_flag = (sizeof(T_FIELD) == sizeof(ULONGLONG)) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
        bool is_by_ord = (desc->u1.Ordinal & ordinal_flag) != 0;
        if (!is_by_ord) {
            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
            if (!validate_ptr(modulePtr, module_size, by_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
                break;
            }
        }
        //when the callback is called, all the pointers should be already verified
        if (!callback->processThunks(lib_name, (ULONG_PTR)&thunks[index], (ULONG_PTR)&callers[index])) {
            is_ok = false;
        }
    }
    return is_ok;
}

//Walk through the table of imported DLLs (starting from the given descriptor) and execute the callback each time when the new record was found
bool process_dlls(BYTE* modulePtr, size_t module_size, IMAGE_IMPORT_DESCRIPTOR *first_desc, IN ImportThunksCallback *callback)
{
    bool isAllFilled = true;
#ifdef _DEBUG
    std::cout << "---IMP---" << std::endl;
#endif
    const bool is64 = is64bit((BYTE*)modulePtr);
    IMAGE_IMPORT_DESCRIPTOR* lib_desc = nullptr;

    for (size_t i = 0; true; i++) {
        lib_desc = &first_desc[i];
        if (!validate_ptr(modulePtr, module_size, lib_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        if (!peconv::is_valid_import_name(modulePtr, module_size, lib_name)) {
            //invalid name
            return false;
        }
        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) {
            thunk_addr = lib_desc->FirstThunk;
        }
#ifdef _DEBUG
        std::cout << "Imported Lib: " << std::hex << lib_desc->FirstThunk << " : " << std::hex << lib_desc->OriginalFirstThunk << " : " << lib_desc->Name << std::endl;
#endif
        size_t all_solved = false;
        if (is64) {
            all_solved = process_imp_functions_tpl<ULONGLONG, IMAGE_THUNK_DATA64>(modulePtr, module_size, lib_name, call_via, thunk_addr, callback);
        }
        else {
            all_solved = process_imp_functions_tpl<DWORD, IMAGE_THUNK_DATA32>(modulePtr, module_size, lib_name, call_via, thunk_addr, callback);
        }
        if (!all_solved) {
            isAllFilled = false;
        }
    }
#ifdef _DEBUG
    printf("---------\n");
#endif
    return isAllFilled;
}

bool peconv::process_import_table(IN BYTE* modulePtr, IN SIZE_T moduleSize, IN ImportThunksCallback *callback)
{
    if (moduleSize == 0) { //if not given, try to fetch
        moduleSize = peconv::get_image_size((const BYTE*)modulePtr);
    }
    if (moduleSize == 0) return false;

    IMAGE_DATA_DIRECTORY *importsDir = get_directory_entry((BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importsDir) {
        return true; //no import table
    }
    const DWORD impAddr = importsDir->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR *first_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + (ULONG_PTR)modulePtr);
    if (!peconv::validate_ptr(modulePtr, moduleSize, first_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
        return false;
    }
    return process_dlls(modulePtr, moduleSize, first_desc, callback);
}

bool peconv::load_imports(BYTE* modulePtr, t_function_resolver* func_resolver)
{
    size_t moduleSize = peconv::get_image_size((const BYTE*)modulePtr);
    if (moduleSize == 0) return false;

    bool is64 = is64bit((BYTE*)modulePtr);
    bool is_loader64 = false;
#ifdef _WIN64
    is_loader64 = true;
#endif
    if (is64 != is_loader64) {
        std::cerr << "[ERROR] Loader/Payload bitness mismatch.\n";
        return false;
    }

    default_func_resolver default_res;
    if (!func_resolver) {
        func_resolver = (t_function_resolver*)&default_res;
    }

    FillImportThunks callback(modulePtr, moduleSize, func_resolver);
    return peconv::process_import_table(modulePtr, moduleSize, &callback);
}

// A valid name must contain printable characters. Empty name is also acceptable (may have been erased)
bool peconv::is_valid_import_name(const PBYTE modulePtr, const size_t moduleSize, LPSTR lib_name)
{
    while (true) {
        if (!peconv::validate_ptr(modulePtr, moduleSize, lib_name, sizeof(char))) {
            return false;
        }
        char next_char = *lib_name;
        if (next_char == '\0') break;

        if (next_char <= 0x20 || next_char >= 0x7E) {
            return false;
        }
        lib_name++;
    }
    return true;
}

bool peconv::has_valid_import_table(const PBYTE modulePtr, size_t moduleSize)
{
    IMAGE_DATA_DIRECTORY *importsDir = get_directory_entry((BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    const DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    DWORD parsedSize = 0;
    size_t valid_records = 0;

    while (true) { //size of the import table doesn't matter
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);
        if (!peconv::validate_ptr(modulePtr, moduleSize, lib_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return false;
        }
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        if (!is_valid_import_name(modulePtr, moduleSize, lib_name)) return false;

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        DWORD *thunks = (DWORD*)((ULONGLONG)modulePtr + thunk_addr);
        if (!peconv::validate_ptr(modulePtr, moduleSize, thunks, sizeof(DWORD))) return false;

        DWORD *callers = (DWORD*)((ULONGLONG)modulePtr + call_via);
        if (!peconv::validate_ptr(modulePtr, moduleSize, callers, sizeof(DWORD))) return false;

        valid_records++;
    }

    return (valid_records > 0);
}
