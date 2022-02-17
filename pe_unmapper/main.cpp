#include <iostream>
#include <tchar.h>
#include <peconv.h>
using namespace peconv;

#define VERSION "1.0"

#define PARAM_OUT_FILE   TEXT("/out")
#define PARAM_BASE       TEXT("/base")
#define PARAM_IN_FILE    TEXT("/in")
#define PARAM_MODE       TEXT("/mode")

typedef enum  {
    MODE_VIRTUAL_TO_RAW = 'U',
    MODE_RAW_TO_VIRTUAL = 'M',
    MODE_REALIGN = 'R',
    MODES_COUNT = 3
} t_map_modes;

typedef struct {
    std::tstring in_file;
    std::tstring out_file;
    ULONGLONG load_base;
    t_map_modes mode;
} t_unmapper_params;

void init_params(t_unmapper_params &params)
{
    params.in_file = TEXT("");
    params.out_file = TEXT("out.exe");
    params.load_base = 0;
    params.mode = MODE_VIRTUAL_TO_RAW;
}

std::tstring mode_to_string(const t_map_modes mode)
{
    switch (mode) {
    case MODE_VIRTUAL_TO_RAW:
        return TEXT("UNMAP (Virtual to Raw)");
    case MODE_RAW_TO_VIRTUAL:
        return TEXT("MAP (Raw to Virtual)");
    case MODE_REALIGN:
        return TEXT("REALIGN (Virtual to Raw, where: Raw == Virtual)");
    }
    return TEXT("Undefined");
}

t_map_modes parse_mode(LPCTSTR arg)
{
    if (!arg) return MODE_VIRTUAL_TO_RAW;
    char mode_val = _toupper(arg[0]);
    return t_map_modes(mode_val);
}


bool remap_pe_file(t_unmapper_params &params)
{
    if (params.in_file.length() == 0 || params.out_file.length() == 0) return false;
    //Read input module:
    std::tcout << TEXT("Input file: ") << params.in_file << TEXT("\n");

    size_t in_size = 0;
    BYTE* in_buf = peconv::read_from_file(params.in_file.c_str(), in_size);
    if (!in_buf) {
        std::tcerr << TEXT("[-] Cannot load file: ") << params.in_file << TEXT("\n");
        return false;
    }

    BYTE* out_buf = nullptr;
    size_t out_size = 0;
    std::tcout << TEXT("[*] Mode: ") << mode_to_string(params.mode) << TEXT("\n");
    switch (params.mode) {
        case MODE_VIRTUAL_TO_RAW:
        {
            ULONGLONG load_base = params.load_base;
            if (!load_base) {
                load_base = peconv::find_base_candidate(in_buf, in_size);
                std::tcout << TEXT("[!] Load base not supplied! Using autosearch...\n");
                std::tcout << TEXT("[*] Found possible relocation base: ") << std::hex << load_base << TEXT("\n");
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
                    std::tcout << TEXT("Could not relocate the module!\n");
                }
                if (params.load_base) {
                    if (relocate_module(out_buf, out_size, (ULONGLONG)params.load_base)) {
                        peconv::update_image_base(out_buf, params.load_base);
                        std::tcout << TEXT("[*] Changed image base to: ") << std::hex << params.load_base << TEXT("\n");
                    }
                }
            }
        };
        break;
        case MODE_REALIGN:
        {
            if (peconv::is_pe_raw(in_buf, in_size)) {
                std::tcout << TEXT("[!] First you need to convert your PE to Virtual format\n");
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
        std::tcerr << "Failed to save file: " << params.out_file << "\n";
    }
    peconv::free_pe_buffer(in_buf, in_size);
    peconv::free_pe_buffer(out_buf, out_size);

    return isOk;
}

void print_help()
{
    std::tcout << TEXT("Required: \n");

    std::tcout << PARAM_IN_FILE;
    std::tcout << TEXT("\t: Input file name\n");

    std::tcout << TEXT("\nOptional: \n");

    std::tcout << PARAM_BASE;
    std::tcout << TEXT("\t: Base address where the image was loaded: in hex\n");

    std::cout << PARAM_OUT_FILE;
    std::cout << TEXT("\t: Output file name\n");

    std::tcout << PARAM_MODE;
    std::tcout << TEXT("\t: Choose the conversion mode:\n");
    std::tcout << TEXT("\t ") << (TCHAR) MODE_VIRTUAL_TO_RAW << TEXT(": ") << mode_to_string(MODE_VIRTUAL_TO_RAW) << TEXT(" [DEFAULT]\n");
    std::tcout << TEXT("\t ") << (TCHAR) MODE_RAW_TO_VIRTUAL << TEXT(": ") << mode_to_string(MODE_RAW_TO_VIRTUAL) << TEXT("\n");
    std::tcout << TEXT("\t ") << (TCHAR) MODE_REALIGN << TEXT(": ") << mode_to_string(MODE_REALIGN) << TEXT("\n");
}

int _tmain(int argc, LPTSTR argv[])
{
    t_unmapper_params params;
    init_params(params);

    if (argc < 3) {
        std::tcout << TEXT("PE Unmapper v") << VERSION  << TEXT("\n")
             << TEXT("URL: https://github.com/hasherezade/libpeconv\n");
        std::tcout << TEXT("Args:\n\n");
        print_help();
        std::tcout << TEXT("---") << std::endl;
        system("pause");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (!_tcscmp(argv[i], PARAM_MODE) && ((i + 1) < argc) && argv[i + 1] != NULL) {
            params.mode = parse_mode(argv[i + 1]);
        }
        else if (!_tcscmp(argv[i], PARAM_OUT_FILE) && (i + 1) < argc) {
            params.out_file = argv[i + 1];
        }
        else if (!_tcscmp(argv[i], PARAM_IN_FILE) && (i + 1) < argc) {
            params.in_file = argv[i + 1];
        }
        else if (!_tcscmp(argv[i], PARAM_BASE) && (i + 1) < argc) {
            ULONGLONG loadBase = 0;
            if (_stscanf(argv[i + 1], TEXT("%llX"), &loadBase) == 0) {
                _stscanf(argv[i + 1], TEXT("%#llX"), &loadBase);
            }
            params.load_base = loadBase;
        }
    }

    if (remap_pe_file(params)) {
        std::tcout << TEXT("Saved output to: ") << params.out_file << std::endl;
        return 0;
    }
    return -1;
}
