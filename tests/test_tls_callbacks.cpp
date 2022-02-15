#include "test_tls_callbacks.h"

#include <peconv.h>
using namespace peconv;

#include <iostream>
#include <string>
#include <map>

int tests::test_load_with_tls_callbacks(LPCTSTR path)
{

    if (path == NULL) {
        std::cerr << "Supply the path to the app" << std::endl;
        return -1;
    }
    std::cout << "Trying to load: " << path << std::endl;
    size_t v_size = 0;

    BYTE* loaded_pe = peconv::load_pe_executable(path, v_size);
    if (!loaded_pe) {
        return -1;
    }

    run_tls_callbacks(loaded_pe, v_size);

    ULONGLONG ep_exp_offset = (ULONGLONG) loaded_pe + peconv::get_entry_point_rva(loaded_pe);
    void (_cdecl *ep_func)() = (void (_cdecl *)()) (ep_exp_offset);
    std::cout << "Calling entry point:" <<std::endl;
    ep_func();
    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}
