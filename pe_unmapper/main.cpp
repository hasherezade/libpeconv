#include <stdio.h>
#include "peconv.h"

bool remap_pe_file(IN const char* filename, IN const char* out_filename, ULONGLONG loadBase)
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

    size_t raw_size = 0;
    BYTE* out_buf = pe_virtual_to_raw(in_buf, size, loadBase, raw_size, false);
    if (!out_buf) {
         VirtualFree(in_buf, size, MEM_RELEASE);
         return false;
    }
    // Write output
    bool isOk = false;
    f = fopen(out_filename, "wb");
    if (f) {
        fwrite(out_buf, 1, raw_size, f);
        fclose(f);
        isOk = true;
    }

    VirtualFree(in_buf, size, MEM_RELEASE);
    free_pe_module(out_buf, raw_size);

    return isOk;
}


int main(int argc, char *argv[])
{
    char* version = "0.2";
    char*  filename = NULL;
    char* out_filename = "out.exe";
    ULONGLONG loadBase = 0;
    if (argc < 3) {
        printf("[ pe_unmapper v%s ]\n\n", version);
        printf("Args: <input file> <load base: in hex> [*output file]\n");
        printf("* - optional\n");
        system("pause");
        return -1;
    }
    filename = argv[1];
    if (sscanf(argv[2],"%llX", &loadBase) == 0) {
        sscanf(argv[2],"%#llX", &loadBase);
    }

    if (argc > 3) {
        out_filename = argv[3];
    }
    //BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &outputSize, bool rebuffer=true);
    if (remap_pe_file(filename, out_filename, loadBase)) {
        printf("Success!\n");
        printf("Saved output to: %s\n", out_filename);
    } else {
        printf("Failed!\n");
    }
    system("pause");
    return 0;
}
