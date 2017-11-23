#include "pe_loader.h"

#include "relocate.h"
#include "load_imports.h"

BYTE* load_pe_module(char *filename, OUT size_t &v_size, bool executable, bool relocate)
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
    CloseHandle(mapping);
    CloseHandle(file);
    return mappedDLL;
}

LPVOID load_pe_executable(char *my_path, OUT size_t &v_size)
{
#if _DEBUG
    printf("Module: %s\n", my_path);
#endif
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(my_path, v_size, true, true);
    if (!loaded_pe) {
        printf("Loading failed!\n");
        return NULL;
    }
#if _DEBUG
    printf("Loaded at: %p\n", loaded_pe);
#endif
    if (!load_imports(loaded_pe)) {
        printf("[-] Loading imports failed!");
        free_pe_buffer(loaded_pe, v_size);
        return NULL;
    }
    return loaded_pe;
}
