#include "peconv/imports_loader.h"

#include <iostream>

using namespace peconv;

template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
bool solve_imported_funcs(BYTE* modulePtr, LPSTR lib_name, DWORD call_via, DWORD thunk_addr, T_FIELD ordinal_flag, t_function_resolver* func_resolver)
{
    if (!func_resolver) {
        //no resolver given, nothing to do...
        return false;
    }
    const size_t module_size = peconv::get_image_size(modulePtr);
    // do you want to overwrite functions that are already filled?
    const bool allow_overwrite = true;

    T_FIELD *thunks = (T_FIELD*)((ULONGLONG)modulePtr + thunk_addr);
    T_FIELD *callers = (T_FIELD*)((ULONGLONG)modulePtr + call_via);

    for (size_t index = 0; true ; index++) {
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
        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled
        if (!allow_overwrite && (thunks[index] != callers[index])) {
            continue; //skip
        }
        LPVOID thunk_ptr = &thunks[index];
        T_IMAGE_THUNK_DATA* desc = reinterpret_cast<T_IMAGE_THUNK_DATA*>(thunk_ptr);
        if (!validate_ptr(modulePtr, module_size, desc, sizeof(T_IMAGE_THUNK_DATA))) {
            break;
        }
        if (desc->u1.Function == NULL) {
            break;
        }
        PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
        if (!validate_ptr(modulePtr, module_size, by_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
            break;
        }
        FARPROC hProc = nullptr;
        if (desc->u1.Ordinal & ordinal_flag) {
            T_FIELD raw_ordinal = desc->u1.Ordinal & (~ordinal_flag);
#ifdef _DEBUG
            std::cout << "raw ordinal: " << std::hex << raw_ordinal << std::endl;
#endif
            hProc = func_resolver->resolve_func(lib_name, MAKEINTRESOURCEA(raw_ordinal));

        } else {
            LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
#ifdef _DEBUG
            std::cout << "name: " << func_name << std::endl;
#endif
            hProc = func_resolver->resolve_func(lib_name, func_name);
        }
        if (!hProc) {
#ifdef _DEBUG
            std::cerr << "Could not resolve the function!" << std::endl;
#endif
            continue;
        }
        //fill the address:
        callers[index] = reinterpret_cast<T_FIELD>(hProc);
    }
    return true;
}

bool solve_imported_funcs_b64(BYTE* modulePtr, LPSTR lib_name, DWORD call_via, DWORD thunk_addr, t_function_resolver* func_resolver)
{
    return solve_imported_funcs<ULONGLONG,IMAGE_THUNK_DATA64>(modulePtr, lib_name, call_via, thunk_addr, IMAGE_ORDINAL_FLAG64, func_resolver);
}

bool solve_imported_funcs_b32(BYTE* modulePtr, LPSTR lib_name, DWORD call_via, DWORD thunk_addr, t_function_resolver* func_resolver)
{
    return solve_imported_funcs<DWORD,IMAGE_THUNK_DATA32>(modulePtr, lib_name, call_via, thunk_addr, IMAGE_ORDINAL_FLAG32, func_resolver);
}

bool peconv::imports_walker(BYTE* modulePtr, t_on_import_found import_found_callback, t_function_resolver* func_resolver)
{
    IMAGE_DATA_DIRECTORY *importsDir = get_directory_entry((BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    const size_t module_size = peconv::get_image_size(modulePtr);
    DWORD maxSize = importsDir->Size;
    DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    bool isAllFilled = true;
    DWORD parsedSize = 0;
#ifdef _DEBUG
    std::cout << "---IMP---" << std::endl;
#endif
    while (parsedSize < maxSize) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        if (!validate_ptr(modulePtr, module_size, lib_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }
#ifdef _DEBUG
        std::cout <<"Imported Lib: " << std::hex << lib_desc->FirstThunk << " : " << std::hex << lib_desc->OriginalFirstThunk << " : " << lib_desc->Name << std::endl;
#endif
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        if (!validate_ptr(modulePtr, module_size, lib_name, sizeof(char))) {
            break;
        }
#ifdef _DEBUG
        std::cout <<"name: " << lib_name << std::endl;
#endif

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        bool all_solved = import_found_callback(modulePtr, lib_name, call_via, thunk_addr, func_resolver);
        if (!all_solved) {
            isAllFilled = false;
        }
    }
#ifdef _DEBUG
    printf("---------\n");
#endif
    return isAllFilled;
}

//fills handles of mapped pe file
bool peconv::load_imports(BYTE* modulePtr, t_function_resolver* func_resolver)
{
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
    if (func_resolver == NULL) {
        func_resolver = (t_function_resolver*)&default_res;
    }

    bool isAllFilled = false;
    if (is64) {
        
        isAllFilled = peconv::imports_walker(modulePtr, solve_imported_funcs_b64, func_resolver);
    } else {
        isAllFilled = peconv::imports_walker(modulePtr, solve_imported_funcs_b32, func_resolver);
    }
    return isAllFilled;
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

    const DWORD maxSize = importsDir->Size;
    const DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    bool isAllFilled = true;
    DWORD parsedSize = 0;

    size_t valid_records = 0;

    while (parsedSize < maxSize) {
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
