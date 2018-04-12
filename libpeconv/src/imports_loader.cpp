#include "peconv/imports_loader.h"

#include <iostream>

using namespace peconv;

template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
bool solve_imported_funcs(LPSTR lib_name, DWORD call_via, DWORD thunk_addr, BYTE* modulePtr, T_FIELD ordinal_flag, t_function_resolver* func_resolver)
{
    if (func_resolver == NULL) return false;

    const bool allow_overwrite = true;

    T_FIELD *thunks = (T_FIELD*)((ULONGLONG)modulePtr + thunk_addr);
    T_FIELD *callers = (T_FIELD*)((ULONGLONG)modulePtr + call_via);

    size_t index = 0;

    do {
        LPVOID call_via_ptr = &callers[index];
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = &thunks[index];
        if (thunk_ptr == NULL) break;

        T_FIELD *thunk_val = (T_FIELD*)thunk_ptr;
        T_FIELD *call_via_val = (T_FIELD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }

        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled
        if (!allow_overwrite && (*thunk_val != *call_via_val)) {
            index++;
            continue; //skip
        }
        T_IMAGE_THUNK_DATA* desc = (T_IMAGE_THUNK_DATA*) thunk_ptr;
        if (desc->u1.Function == NULL) break;

        PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);

        FARPROC hProc = NULL;
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
        if (hProc != NULL) {
            callers[index] = reinterpret_cast<T_FIELD>(hProc);
        } else {
#ifdef _DEBUG
            std::cerr << "Could not resolve the function!" << std::endl;
#endif
        }

        index++;
    } while (true);
    return true;
}

bool solve_imported_funcs_b64(LPSTR lib_name, DWORD call_via, DWORD thunk_addr, BYTE* modulePtr, t_function_resolver* func_resolver)
{
    return solve_imported_funcs<ULONGLONG,IMAGE_THUNK_DATA64>(lib_name, call_via, thunk_addr, modulePtr, IMAGE_ORDINAL_FLAG64, func_resolver);
}

bool solve_imported_funcs_b32(LPSTR lib_name, DWORD call_via, DWORD thunk_addr, BYTE* modulePtr, t_function_resolver* func_resolver)
{
    return solve_imported_funcs<DWORD,IMAGE_THUNK_DATA32>(lib_name, call_via, thunk_addr, modulePtr, IMAGE_ORDINAL_FLAG32, func_resolver);
}

bool peconv::imports_walker(BYTE* modulePtr, t_on_import_found import_found_callback, t_function_resolver* func_resolver)
{
    IMAGE_DATA_DIRECTORY *importsDir = get_directory_entry((BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

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
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }
#ifdef _DEBUG
        std::cout <<"Imported Lib: " << std::hex << lib_desc->FirstThunk << " : " << std::hex << lib_desc->OriginalFirstThunk << " : " << lib_desc->Name << std::endl;
#endif
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
#ifdef _DEBUG
        std::cout <<"name: " << lib_name << std::endl;
#endif

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        bool all_solved = import_found_callback(lib_name, call_via, thunk_addr, modulePtr, func_resolver);
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
    default_func_resolver default_res;
    if (func_resolver == NULL) {
        func_resolver = (t_function_resolver*) &default_res;
    }
    bool is64 = is64bit((BYTE*)modulePtr);

    bool isAllFilled = false;
    if (is64) {
        
        isAllFilled = peconv::imports_walker(modulePtr, solve_imported_funcs_b64, func_resolver);
    } else {
        isAllFilled = peconv::imports_walker(modulePtr, solve_imported_funcs_b32, func_resolver);
    }
    return isAllFilled;
}
