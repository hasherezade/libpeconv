#include "test_format_detect.h"

using namespace peconv;

void printFromat(bool isRaw)
{
    if (isRaw) {
        std::cout << "PE is in the RAW format\n";
    }
    else {
        std::cout << "PE is in the VIRTUAL format\n";
    }
}

int tests::check_pe_format(const char *my_path)
{
    size_t pe_size = 0;
    std::cout << "Module: " << my_path << "\n";
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = peconv::load_file(my_path, pe_size);
    if (!loaded_pe) {
        std::cout << "Loading failed!\n";
        return -1;
    }
    bool isRaw = peconv::is_pe_raw(loaded_pe, pe_size);
    bool isRaw2 = false;
    if (isRaw) {
        size_t v_size = 0;
        BYTE* virtual_pe = peconv::load_pe_module(my_path, v_size, false, false);
        if (!virtual_pe) {
            std::cout << "Mapping failed!\n";
            return -1;
        }
        isRaw2 = peconv::is_pe_raw(virtual_pe, v_size);
        peconv::free_pe_buffer(virtual_pe);
    }
    peconv::free_pe_buffer(loaded_pe);

    std::cout << "Test 1:\n\t";
    printFromat(isRaw);
    std::cout << "Test 2:\n\t";
    printFromat(isRaw2);
    if (isRaw && !isRaw2) {
        return 0; // status OK
    }
    return 1;
}
