#include <stdio.h>

#include "peconv.h"
using namespace peconv;

#define VERSION "0.4"

#define PARAM_RAW_TO_VIRTUAL "/r2v"
#define PARAM_OUT_FILE "/out"
#define PARAM_BASE "/base"
#define PARAM_IN_FILE "/in"
#define PARAM_REALIGN_RAW "/vraw"

typedef struct {
    std::string in_file;
    std::string out_file;
    ULONGLONG load_base;
    bool mode_r_to_v;
    bool realign_raw;
} t_unmapper_params;

void init_params(t_unmapper_params &params)
{
    params.in_file = "";
    params.out_file = "out.exe";
    params.load_base = 0;
    params.mode_r_to_v = false;
    params.realign_raw = false;
}

bool remap_pe_file(t_unmapper_params &params)
{
    if (params.in_file.length() == 0 || params.out_file.length() == 0) return false;
    //Read input module:
    std::cout << "filename: " << params.in_file << "\n";

    size_t in_size = 0;
    BYTE* in_buf = peconv::read_from_file(params.in_file.c_str(), in_size);

    BYTE* out_buf = nullptr;
    size_t out_size = 0;

    if (params.mode_r_to_v) {
        std::cout << "MODE: Raw -> Virtual\n";
        out_buf = peconv::load_pe_module(in_buf, in_size, out_size, false, false);
        if (out_buf) {
           ULONGLONG base = peconv::get_image_base(out_buf);
           if (!relocate_module(out_buf, out_size, (ULONGLONG) base)) {
               std::cout << "Could not relocate the module!\n";
           }
        }
    }
    else {
        std::cout << "MODE: Virtual -> Raw\n";
        if (params.realign_raw) {
            std::cout << "Realign Raw to Virtual\n";
            out_buf = peconv::pe_realign_raw_to_virtual(in_buf, in_size, params.load_base, out_size);
        }
        else {
            out_buf = peconv::pe_virtual_to_raw(in_buf, in_size, params.load_base, out_size, false);
        }
    }
    if (!out_buf) {
        std::cerr << "Failed to convert!\n";
        peconv::free_pe_buffer(in_buf, in_size);
        return false;
    }
    // Write output
    bool isOk = peconv::dump_to_file(params.out_file.c_str(), out_buf, out_size);
    if (!isOk) {
        std::cerr << "Failed to save file: " << params.out_file << "\n";
    }
    peconv::free_pe_buffer(in_buf, in_size);
    peconv::free_pe_buffer(out_buf, out_size);

    return isOk;
}

void print_help()
{
    std::cout << "Required: \n";

    std::cout << PARAM_IN_FILE;
    std::cout << "\t: Input file name\n";
    std::cout << PARAM_BASE;
    std::cout << "\t: Base address where the image was loaded: in hex\n";

    std::cout << "\nOptional: \n";
    
    std::cout << PARAM_OUT_FILE;
    std::cout << "\t: Output file name\n";

    std::cout << PARAM_RAW_TO_VIRTUAL;
    std::cout << "\t: Switch conversion mode: raw input -> virtual output\n";
    std::cout << "\t(Default mode: virtual input -> raw output)\n";

    std::cout << PARAM_REALIGN_RAW;
    std::cout << "\t: Change raw alignment: copy from virtual\n";
}

int main(int argc, char *argv[])
{
    t_unmapper_params params;
    init_params(params);

    if (argc < 3) {
        std::cout << "[ pe_unmapper v" << VERSION  << "]\n";
        print_help();
        std::cout << "---" << std::endl;
        system("pause");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PARAM_RAW_TO_VIRTUAL)) {
            params.mode_r_to_v = true;
        }
        else if (!strcmp(argv[i], PARAM_REALIGN_RAW)) {
            params.realign_raw = true;
        }
        else if (!strcmp(argv[i], PARAM_OUT_FILE) && (i + 1) < argc) {
            params.out_file = argv[i + 1];
        }
        else if (!strcmp(argv[i], PARAM_IN_FILE) && (i + 1) < argc) {
            params.in_file = argv[i + 1];
        }
        else if (!strcmp(argv[i], PARAM_BASE) && (i + 1) < argc) {
            ULONGLONG loadBase = 0;
            if (sscanf(argv[i + 1], "%llX", &loadBase) == 0) {
                sscanf(argv[i + 1], "%#llX", &loadBase);
            }
            params.load_base = loadBase;
        }
    }

    if (remap_pe_file(params)) {
        std::cout << "Saved output to: " << params.out_file << std::endl;
        return 0;
    }
    return -1;
}
