#include "test_exceptions.h"

#include <peconv.h>
using namespace peconv;

#include <iostream>
#include <string>
#include <map>

int tests::test_load_with_exception_table(LPCTSTR path)
{
    if (path == NULL) {
        std::cerr << "Supply the path to the app" << std::endl;
        return -1;
    }
    std::wcout << "Trying to load: " << path << std::endl;
    size_t v_size = 0;

    BYTE* loaded_pe = peconv::load_pe_executable(path, v_size);
    if (!loaded_pe) {
        return -1;
    }
    std::wcout << "Trying to set up exceptions: " << path << std::endl;
    if (!peconv::setup_exceptions(loaded_pe, v_size)) {
        std::cerr << "[+] Failed to add the exception table\n";
    }
    else {
#ifdef _DEBUG
        std::wcout << "[+] The exception table was added\n";
#endif
    }
    std::wcout << __FUNCTION__ << ": Throwing exception:" << std::endl;
    __try {
        peconv::run_tls_callbacks(loaded_pe, v_size);

        ULONGLONG ep_exp_offset = (ULONGLONG)loaded_pe + peconv::get_entry_point_rva(loaded_pe);
        void(_cdecl * ep_func)() = (void(_cdecl*)()) (ep_exp_offset);
        std::wcout << "Calling entry point:" << std::endl;
        ep_func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::wcout << "Exception captured by the caller" << std::endl;
    }
    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}
