#include <stdio.h>

#include "peconv.h"
using namespace peconv;

bool remap_pe_file(IN const char* filename, IN const char* out_filename, ULONGLONG loadBase, bool mode_v_to_r)
{
    if (filename == NULL || out_filename == NULL) return false;
    //Read input module:
    printf("filename: %s\n", filename);

    size_t size = 0;
    BYTE* in_buf = peconv::read_from_file(filename, size);

    BYTE* out_buf = NULL;
    
    size_t out_size = 0;
    if (mode_v_to_r) {
        printf("MODE: Virtual -> Raw\n");
        out_buf = peconv::pe_virtual_to_raw(in_buf, size, loadBase, out_size, false);
    } else {
        printf("MODE: Raw -> Virtual\n");
        out_buf = peconv::load_pe_module(in_buf, size, out_size, false, false);
        if (out_buf) {
           ULONGLONG base = peconv::get_image_base(out_buf);
           if (!relocate_module(out_buf, out_size, (ULONGLONG) base)) {
               printf("Could not relocate the module!\n");
           }
        }
    }
    if (!out_buf) {
        peconv::free_pe_buffer(in_buf, size);
        return false;
    }
    // Write output
    bool isOk = peconv::dump_to_file(out_filename,out_buf,out_size);

    peconv::free_pe_buffer(in_buf, size);
    peconv::free_pe_buffer(out_buf, out_size);

    return isOk;
}

int main(int argc, char *argv[])
{
    char* version = "0.3.1";
    char*  filename = NULL;
    char* out_filename = "out.exe";
    const char mode_switch[] = "-v";
    ULONGLONG loadBase = 0;
    bool mode_v_to_r = true;
    if (argc < 3) {
        printf("[ pe_unmapper v%s ]\n\n", version);
        printf("Args: <input file> <load base: in hex> [*output file] [*%s]\n", mode_switch);
        printf("* - optional\n");
        printf("---\n");
        printf("Default mode:\n\tvirtual input -> raw output\n", mode_switch);
        printf("%s : switches remapping mode into:\n\traw input -> virtual output\n", mode_switch);
        printf("---\n");
        system("pause");
        return -1;
    }
    filename = argv[1];
    if (sscanf(argv[2],"%llX", &loadBase) == 0) {
        sscanf(argv[2],"%#llX", &loadBase);
    }

    if (argc > 3) {
        if (strcmp(argv[3], mode_switch) != 0) {
            out_filename = argv[3];
        }
    }
    if (argc > 3) {
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], mode_switch) == 0)
                mode_v_to_r = false;
        }
    }

    if (remap_pe_file(filename, out_filename, loadBase, mode_v_to_r)) {
        printf("Success!\n");
        printf("Saved output to: %s\n", out_filename);
    } else {
        printf("Failed!\n");
    }
    system("pause");
    return 0;
}
