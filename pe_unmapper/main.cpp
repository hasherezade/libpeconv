#include <stdio.h>

#include "peconv.h"
using namespace peconv;

bool remap_pe_file(IN const char* filename, IN const char* out_filename, ULONGLONG loadBase, bool mode_v_to_r)
{
    if (filename == NULL || out_filename == NULL) return false;
    //Read input module:
    printf("filename: %s\n", filename);
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Cannot open file!\n");
        return false;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    printf("size = %#llx = %lld\n", static_cast<ULONGLONG>(size), static_cast<ULONGLONG>(size));
    BYTE* in_buf = (BYTE*) VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    fseek(f, 0, SEEK_SET);
    fread(in_buf, 1, size, f);
    fclose(f);
    f = NULL;

    BYTE* out_buf = NULL;
    
    size_t out_size = 0;
    if (mode_v_to_r) {
        printf("Virtual to raw:\n");
        out_buf = peconv::pe_virtual_to_raw(in_buf, size, loadBase, out_size, false);
    } else {
        printf("Raw to virtual:\n");
        out_buf = peconv::load_pe_module(in_buf, size, out_size, false, false);
        if (out_buf) {
           ULONGLONG base = peconv::get_image_base(out_buf);
           if (!relocate_module(out_buf, out_size, (ULONGLONG) base)) {
               printf("Could not relocate the module!\n");
           }
        }
    }
    if (!out_buf) {
         VirtualFree(in_buf, size, MEM_RELEASE);
         return false;
    }
    // Write output
    bool isOk = false;
    f = fopen(out_filename, "wb");
    if (f) {
        fwrite(out_buf, 1, out_size, f);
        fclose(f);
        isOk = true;
    }

    VirtualFree(in_buf, size, MEM_RELEASE);
    free_pe_buffer(out_buf, out_size);

    return isOk;
}


int main(int argc, char *argv[])
{
    char* version = "0.3";
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
