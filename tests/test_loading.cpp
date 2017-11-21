#include <stdio.h>
#include <Windows.h>

#include "test_loading.h"

int tests::load_self()
{
    char my_path[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    size_t v_size = 0;
    printf("Module: %s\n", my_path);
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(my_path, v_size);
    if (!loaded_pe) {
        printf("Loading failed!\n");
        return -1;
    }
    bool is_ok = relocate_module(loaded_pe, v_size, (ULONGLONG)loaded_pe);
    if (!is_ok) {
        printf("Could not relocate the module!\n");
    }
    printf("Loaded at: %p\n", loaded_pe);
   
    // Now try to unmap the loaded image using libpeconv:
    size_t raw_size = 0;
    BYTE* unmapped = pe_virtual_to_raw(loaded_pe, v_size, (ULONGLONG)loaded_pe, raw_size, true);
    if (!unmapped || raw_size == 0) {
        printf("Unmapping failed!\n");
        return -1;
    }
    printf("Unmapped at: %p\n", unmapped);

    //Read the original file and compare it with the unmapped module:
    size_t read_size = 0;
    BYTE* file_content = load_file(my_path, read_size);
    if (file_content == NULL) {
        printf("Reading file failed!\n");
        return -1;
    }
    printf("Read size: %d\n", read_size);
    printf("Unmapped size: %d\n", raw_size);
    size_t smaller_size = raw_size < read_size ? raw_size : read_size;
    int res = memcmp(unmapped, file_content, smaller_size);
    if (loaded_pe) {
        free_pe_module(loaded_pe, v_size);
        free_pe_module(unmapped, raw_size);
        printf("Unloaded!\n");
    }
    free_file(file_content, read_size);
    return res;
}
