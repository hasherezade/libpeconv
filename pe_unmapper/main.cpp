#include <iostream>

#include <peconv.h>
using namespace peconv;

#define VERSION "1.0"

#define PARAM_OUT_FILE "/out"
#define PARAM_BASE "/base"
#define PARAM_IN_FILE "/in"
#define PARAM_MODE "/mode"

typedef enum  {
    MODE_VIRTUAL_TO_RAW = 'U',
    MODE_RAW_TO_VIRTUAL = 'M',
    MODE_REALIGN = 'R',
    MODES_COUNT = 3
} t_map_modes;

typedef struct {
    std::string in_file;
    std::string out_file;
    ULONGLONG load_base;
    t_map_modes mode;
} t_unmapper_params;

void init_params(t_unmapper_params &params)
{
    params.in_file = "";
    params.out_file = "out.exe";
    params.load_base = 0;
    params.mode = MODE_VIRTUAL_TO_RAW;
}

std::string mode_to_string(const t_map_modes mode)
{
    switch (mode) {
    case MODE_VIRTUAL_TO_RAW:
        return "UNMAP (Virtual to Raw)";
    case MODE_RAW_TO_VIRTUAL:
        return "MAP (Raw to Virtual)";
    case MODE_REALIGN:
        return "REALIGN (Virtual to Raw, where: Raw == Virtual)";
    }
    return "Undefined";
}

t_map_modes parse_mode(char *arg)
{
    if (!arg) return MODE_VIRTUAL_TO_RAW;
    char mode_val = toupper(arg[0]);
    return t_map_modes(mode_val);
}


bool remap_pe_file(t_unmapper_params &params)
{
    if (params.in_file.length() == 0 || params.out_file.length() == 0) return false;
    //Read input module:
    std::cout << "Input file: " << params.in_file << "\n";

    size_t in_size = 0;
    BYTE* in_buf = peconv::read_from_file(params.in_file.c_str(), in_size);
    if (!in_buf) {
        std::cerr << "[-] Cannot load file: " << params.in_file << "\n";
        return false;
    }

    BYTE* out_buf = nullptr;
    size_t out_size = 0;
    std::cout << "[*] Mode: " << mode_to_string(params.mode) << "\n";
    switch (params.mode) {
        case MODE_VIRTUAL_TO_RAW:
        {
            ULONGLONG load_base = params.load_base;
            if (!load_base) {
                load_base = peconv::find_base_candidate(in_buf, in_size);
                std::cout << "[!] Load base not supplied! Using autosearch...\n";
                std::cout << "[*] Found possible relocation base: " << std::hex << load_base << "\n";
            }
            out_buf = peconv::pe_virtual_to_raw(in_buf, in_size, load_base, out_size, false);
        };
        break;
        case MODE_RAW_TO_VIRTUAL:
        {
            out_buf = peconv::load_pe_module(in_buf, in_size, out_size, false, false);
            if (out_buf) {
                ULONGLONG base = peconv::get_image_base(out_buf);
                if (!relocate_module(out_buf, out_size, (ULONGLONG)base)) {
                    std::cout << "Could not relocate the module!\n";
                }
                if (params.load_base) {
                    if (relocate_module(out_buf, out_size, (ULONGLONG)params.load_base)) {
                        peconv::update_image_base(out_buf, params.load_base);
                        std::cout << "[*] Changed image base to: " << std::hex << params.load_base << "\n";
                    }
                }
            }
        };
        break;
        case MODE_REALIGN:
        {
            if (peconv::is_pe_raw(in_buf, in_size)) {
                std::cout << "[!] First you need to convert your PE to Virtual format\n";
            }
            else {
                out_buf = peconv::pe_realign_raw_to_virtual(in_buf, in_size, params.load_base, out_size);
            }
        };
        break;
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

    std::cout << "\nOptional: \n";

    std::cout << PARAM_BASE;
    std::cout << "\t: Base address where the image was loaded: in hex\n";

    std::cout << PARAM_OUT_FILE;
    std::cout << "\t: Output file name\n";

    std::cout << PARAM_MODE;
    std::cout << "\t: Choose the conversion mode:\n";
    std::cout << "\t " << (char) MODE_VIRTUAL_TO_RAW << ": " << mode_to_string(MODE_VIRTUAL_TO_RAW) << " [DEFAULT]\n";
    std::cout << "\t " << (char) MODE_RAW_TO_VIRTUAL << ": " << mode_to_string(MODE_RAW_TO_VIRTUAL) << "\n";
    std::cout << "\t " << (char) MODE_REALIGN << ": " << mode_to_string(MODE_REALIGN) << "\n";
}

int main(int argc, char *argv[])
{
    t_unmapper_params params;
    init_params(params);

    if (argc < 3) {
        std::cout << "[ pe_unmapper v" << VERSION  << " ]\n";
        std::cout << "Args:\n\n";
        print_help();
        std::cout << "---" << std::endl;
        system("pause");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PARAM_MODE) && ((i + 1) < argc) && argv[i + 1] != NULL) {
            params.mode = parse_mode(argv[i + 1]);
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
