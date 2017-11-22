#include "pe_loader.h"

#include "relocate.h"
#include "load_imports.h"

LPVOID load_pe_executable(char *my_path)
{
    size_t v_size = 0;
#if _DEBUG
    printf("Module: %s\n", my_path);
#endif
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(my_path, v_size);
    if (!loaded_pe) {
        printf("Loading failed!\n");
        return NULL;
    }
    bool is_ok = relocate_module(loaded_pe, v_size, (ULONGLONG)loaded_pe);
    if (!is_ok) {
        printf("Could not relocate the module!\n");
        free_pe_buffer(loaded_pe, v_size);
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
