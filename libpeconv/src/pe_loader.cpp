#include "peconv/pe_loader.h"

#include "peconv/relocate.h"
#include "peconv/imports_loader.h"
#include "peconv/module_helper.h"
#include "peconv/function_resolver.h"
#include "peconv/exports_lookup.h"

using namespace peconv;

BYTE* peconv::load_pe_module(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, bool executable, bool relocate)
{
    ULONGLONG desired_base = NULL;
    if (relocate && !has_relocations(dllRawData)) {
        desired_base = get_image_base(dllRawData);
    }

    BYTE *mappedDLL = pe_raw_to_virtual(dllRawData, r_size, v_size, executable, desired_base);
    if (mappedDLL) {
        if (relocate && !relocate_module(mappedDLL, v_size, (ULONGLONG)mappedDLL)) {
            printf("Could not relocate the module!");
            free_pe_buffer(mappedDLL, v_size);
            mappedDLL = NULL;
        }
    } else {
        printf("Could not allocate memory at the desired base!\n");
    }
    UnmapViewOfFile(dllRawData);
    return mappedDLL;
}

BYTE* peconv::load_pe_module(const char *filename, OUT size_t &v_size, bool executable, bool relocate)
{
    HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(file == INVALID_HANDLE_VALUE) {
        printf("Cannot open the file!\n");
        return NULL;
    }
    size_t r_size = GetFileSize(file, 0);
    HANDLE mapping  = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
        printf("Cannot map the file!\n");
        CloseHandle(file);
        return NULL;
    }
    
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    
    if (dllRawData == NULL) {
        CloseHandle(mapping);
        CloseHandle(file);
        return NULL;
    }

    BYTE *mappedDLL = load_pe_module(dllRawData, r_size, v_size, executable, relocate);

    CloseHandle(mapping);
    CloseHandle(file);

    return mappedDLL;
}

BYTE* peconv::load_pe_executable(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, t_function_resolver* import_resolver)
{
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(dllRawData, r_size, v_size, true, true);
    if (!loaded_pe) {
        printf("Loading failed!\n");
        return NULL;
    }
#if _DEBUG
    printf("Loaded at: %p\n", loaded_pe);
#endif
    if (!load_imports(loaded_pe, import_resolver)) {
        printf("[-] Loading imports failed!");
        free_pe_buffer(loaded_pe, v_size);
        return NULL;
    }
    return loaded_pe;
}


BYTE* peconv::load_pe_executable(const char *my_path, OUT size_t &v_size, t_function_resolver* import_resolver)
{
#if _DEBUG
    printf("Module: %s\n", my_path);
#endif
    BYTE* loaded_pe = load_pe_module(my_path, v_size, true, true);
    if (!loaded_pe) {
         printf("Loading failed!\n");
        return NULL;
    }
#if _DEBUG
    printf("Loaded at: %p\n", loaded_pe);
#endif
    if (!load_imports(loaded_pe, import_resolver)) {
        printf("[-] Loading imports failed!");
        free_pe_buffer(loaded_pe, v_size);
        return NULL;
    }
    return loaded_pe;
}
