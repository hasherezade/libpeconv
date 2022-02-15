#include "test_loading.h"

#include <iostream>
#include <peconv.h>
using namespace peconv;

int tests::load_self()
{
    TCHAR my_path[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, my_path, MAX_PATH);
    size_t v_size = 0;
    std::cout << "Module: " << my_path << "\n";
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(my_path, v_size, true, true);
    if (!loaded_pe) {
        std::cout << "Loading failed!\n";
        return -1;
    }

    printf("Loaded at: %p\n", loaded_pe);
   
    // Now try to unmap the loaded image using libpeconv:
    size_t raw_size = 0;
    BYTE* unmapped = pe_virtual_to_raw(loaded_pe, v_size, (ULONGLONG)loaded_pe, raw_size, true);
    if (!unmapped || raw_size == 0) {
        std::cout << "Unmapping failed!\n";
        return -1;
    }
    std::cout << "Unmapped at:" << std::hex << (ULONG_PTR)unmapped << "\n";

    //Read the original file and compare it with the unmapped module:
    size_t read_size = 0;
    BYTE* file_content = load_file(my_path, read_size);
    if (file_content == NULL) {
        printf("Reading file failed!\n");
        return -1;
    }
    std::cout << "Read size: " << std::dec << read_size << "\n";
    std::cout << "Unmapped size: " << std::dec << raw_size << "\n";
    size_t smaller_size = raw_size < read_size ? raw_size : read_size;
    int res = memcmp(unmapped, file_content, smaller_size);
    if (loaded_pe) {
        free_pe_buffer(loaded_pe, v_size);
        free_pe_buffer(unmapped, raw_size);
        std::cout << "Unloaded!\n";
    }
    free_file(file_content);
    if (res != 0) {
        std::cout << "Unmapped module is NOT the same as the original!\n";
    }
    return res;
}
