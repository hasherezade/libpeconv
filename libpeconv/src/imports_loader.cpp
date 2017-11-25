#include "peconv/imports_loader.h"

#include <stdio.h>

using namespace peconv;

bool peconv::write_handle(BYTE* modulePtr, ULONGLONG call_via, 
                          HMODULE libBasePtr, LPSTR func_name, 
                          t_get_proc_address get_proc_addr)
{
    const size_t field_size = peconv::is64bit(modulePtr) 
        ? sizeof(ULONGLONG) 
        : sizeof(DWORD);

    FARPROC hProc = get_proc_addr(libBasePtr, func_name);
    if (hProc == NULL) {
        printf("Could not load the function!\n");
        return false;
    }
    LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
    memcpy(call_via_ptr, &hProc, field_size);

#ifdef _DEBUG
    printf("proc addr: %p -> %p\n", hProc, call_via_ptr);
#endif
    return true;
}

bool solve_imported_funcs_b32(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, BYTE* modulePtr, t_load_library load_lib,  t_get_proc_address get_proc_addr)
{
    const bool allow_overwrite = false;
    HMODULE libBasePtr = load_lib(lib_name);
    if (libBasePtr == NULL) {
        printf("Could not load the library!\n");
        return false;
    }
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        DWORD *thunk_val = (DWORD*)thunk_ptr;
        DWORD *call_via_val = (DWORD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }
        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled
        if (*thunk_val != *call_via_val) {
            call_via += sizeof(DWORD);
            thunk_addr += sizeof(DWORD);
            continue; //skip
        }
        IMAGE_THUNK_DATA32* desc = (IMAGE_THUNK_DATA32*) thunk_ptr;
        if (desc->u1.Function == NULL) break;

        PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
        if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
            DWORD raw_ordinal = desc->u1.Ordinal & (~IMAGE_ORDINAL_FLAG32);
#ifdef _DEBUG
            printf("raw ordinal: %x\n", raw_ordinal);
#endif
            
            if (!write_handle(modulePtr, call_via, libBasePtr, MAKEINTRESOURCE(raw_ordinal), get_proc_addr)) {
                return false;
            }
        } else {
            LPSTR func_name = by_name->Name;
#ifdef _DEBUG
            printf("name: %s\n", func_name);
#endif
            if (!write_handle(modulePtr, call_via, libBasePtr, func_name, get_proc_addr)) {
                printf("Could not load the handle!\n");
                return false;
            }
        }
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);
    return true;
}

bool solve_imported_funcs_b64(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, BYTE* modulePtr, t_load_library load_lib,  t_get_proc_address get_proc_addr)
{
    const bool allow_overwrite = false;

    HMODULE libBasePtr = load_lib(lib_name);
    if (libBasePtr == NULL) {
        printf("Could not load the library!\n");
        return false;
    }
    
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        ULONGLONG *thunk_val = (ULONGLONG*)thunk_ptr;
        ULONGLONG *call_via_val = (ULONGLONG*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }
        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled

        if (!allow_overwrite && (*thunk_val != *call_via_val)) {
            call_via += sizeof(ULONGLONG);
            thunk_addr += sizeof(ULONGLONG);
            continue; //skip
        }
        IMAGE_THUNK_DATA64* desc = (IMAGE_THUNK_DATA64*) thunk_ptr;
        if (desc->u1.Function == NULL) break;

        PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
        if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
            ULONGLONG raw_ordinal = desc->u1.Ordinal & (~IMAGE_ORDINAL_FLAG64);
#ifdef _DEBUG
            printf("raw ordinal: %llx\n", raw_ordinal);
#endif
            if (!write_handle(modulePtr, ULONGLONG(call_via), libBasePtr, MAKEINTRESOURCE(raw_ordinal), get_proc_addr)) {
                return false;
            }
        } else {
            LPSTR func_name = by_name->Name;
#ifdef _DEBUG
            printf("name: %s\n", func_name);
#endif
            if (!write_handle(modulePtr, call_via, libBasePtr, func_name, get_proc_addr)) {
                printf("Could not load the handle!\n");
                return false;
            }
        }
        call_via += sizeof(ULONGLONG);
        thunk_addr += sizeof(ULONGLONG);
    } while (true);
    return true;
}

bool peconv::imports_walker(BYTE* modulePtr, t_on_import_found import_found_callback, t_load_library load_lib, t_get_proc_address get_proc_addr)
{
    IMAGE_DATA_DIRECTORY *importsDir = get_pe_directory((BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    DWORD maxSize = importsDir->Size;
    DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    bool isAllFilled = true;
    DWORD parsedSize = 0;
#ifdef _DEBUG
    printf("---IMP---\n");
#endif
    while (parsedSize < maxSize) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }
#ifdef _DEBUG
        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
#endif
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
#ifdef _DEBUG
        printf("name: %s\n", lib_name);
#endif

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        bool all_solved = import_found_callback(lib_name, call_via, thunk_addr, modulePtr, LoadLibraryA, GetProcAddress);
        if (!all_solved) {
            isAllFilled = false;
        }
    }
    if (isAllFilled == false) {
        printf("WARNING: Some libraries are not filled!\nFor this method to work, EXE cannot have other imports than kernel32.dll or user32.dll!\n");
    }
#ifdef _DEBUG
    printf("---------\n");
#endif
    return isAllFilled;
}

//fills handles of mapped pe file
bool peconv::load_imports(BYTE* modulePtr, t_load_library load_lib,  t_get_proc_address get_proc_addr)
{
    bool is64 = is64bit((BYTE*)modulePtr);
    bool isAllFilled = false;
    if (is64) {
        isAllFilled = peconv::imports_walker(modulePtr, solve_imported_funcs_b64, load_lib, get_proc_addr);
    } else {
        isAllFilled = peconv::imports_walker(modulePtr, solve_imported_funcs_b32, load_lib, get_proc_addr);
    }
    return isAllFilled;
}


bool peconv::load_imports(BYTE* modulePtr)
{
    return load_imports(modulePtr, LoadLibraryA,  GetProcAddress);
}