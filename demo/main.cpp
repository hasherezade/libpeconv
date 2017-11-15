#include <stdio.h>
#include "peconv.h"
#include "file_helper.h"

int main(int argc, char *argv[])
{
    size_t v_size = 0;
    printf("Module: %s\n", argv[0]);
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(argv[0], v_size);
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
        system("pause");
        return -1;
    }
    printf("Unmapped at: %p\n", unmapped);

    //Read the original file and compare it with the unmapped module:
    size_t read_size = 0;
    BYTE* file_content = load_file(argv[0], read_size);
    if (file_content == NULL) {
        printf("Reading file failed!\n");
        system("pause");
        return -1;
    }
    printf("Read size: %d\n", read_size);
    printf("Unmapped size: %d\n", raw_size);
    size_t smaller_size = raw_size < read_size ? raw_size : read_size;
    int res = memcmp(unmapped, file_content, smaller_size);
    if (res == 0) {
        printf("[+] Test passed - the unmapped module is the same as the original!\n");
    }
    system("pause");
    if (loaded_pe) {
        free_pe_module(loaded_pe, v_size);
        free_pe_module(unmapped, raw_size);
        printf("Unloaded!\n");
    }
    free_file(file_content, read_size);
    system("pause");
    return res;
}