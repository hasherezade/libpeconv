#include "peconv/pe_loader.h"

#include "peconv/relocate.h"
#include "peconv/imports_loader.h"
#include "peconv/module_helper.h"
#include "peconv/function_resolver.h"
#include "peconv/exports_lookup.h"

#include <iostream>

using namespace peconv;

BYTE* peconv::load_pe_module(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, bool executable, bool relocate)
{
    // by default, allow to load the PE at any base:
    ULONGLONG desired_base = NULL;
    // if relocating is required, but the PE has no relocation table...
    if (relocate && !has_relocations(dllRawData)) {
        // ...enforce loading the PE image at its default base (so that it will need no relocations)
        desired_base = get_image_base(dllRawData);
    }
    // load a virtual image of the PE file at the desired_base address (random if desired_base is NULL):
    BYTE *mappedDLL = pe_raw_to_virtual(dllRawData, r_size, v_size, executable, desired_base);
    if (mappedDLL) {
        //if the image was loaded at its default base, relocate_module will return always true (because relocating is already done)
        if (relocate && !relocate_module(mappedDLL, v_size, (ULONGLONG)mappedDLL)) {
            // relocating was required, but it failed - thus, the full PE image is useless
            printf("Could not relocate the module!");
            free_pe_buffer(mappedDLL, v_size);
            mappedDLL = NULL;
        }
    } else {
        printf("Could not allocate memory at the desired base!\n");
    }
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
    
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, r_size);
    
    if (dllRawData == NULL) {
        CloseHandle(mapping);
        CloseHandle(file);
        return NULL;
    }
    BYTE *mappedDLL = nullptr;
    if (!IsBadReadPtr(dllRawData,r_size)) {
        mappedDLL = load_pe_module(dllRawData, r_size, v_size, executable, relocate);
    } else {
        std::cerr << "[-] oops, mapping of " << filename << " is invalid!" << std::endl;
    }
    UnmapViewOfFile(mapping);
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
