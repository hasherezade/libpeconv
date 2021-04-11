#include "test_imports_mix.h"

using namespace peconv;

int tests::imports_mix(const char *my_path)
{
    size_t v_size = 0;
    std::cout << "Module: " << my_path << "\n";
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = peconv::load_pe_executable(my_path, v_size);
    if (!loaded_pe) {
        std::cout << "Loading failed!\n";
        return -1;
    }

    //calculate the Entry Point of the manually loaded module
    DWORD ep_rva = peconv::get_entry_point_rva(loaded_pe, v_size);
    if (!ep_rva) {
        return -2;
    }
    ULONG_PTR ep_va = ep_rva + (ULONG_PTR)loaded_pe;
    //assuming that the payload is an EXE file (not DLL) this will be the simplest prototype of the main:
    int(*new_main)() = (int(*)())ep_va;

    //call the Entry Point of the manually loaded PE:
    new_main();
    peconv::free_pe_buffer(loaded_pe);
    return 0;
}
