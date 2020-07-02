#include "test_found_base.h"
#include <windows.h>
#include <iostream>
#include <peconv.h>
#include <peconv\find_base.h>

using namespace peconv;

int tests::load_and_check_base(const char *path)
{
    if (!path) {
        return -1;
    }
    size_t v_size = 0;
    BYTE* pe = peconv::load_pe_module(path, v_size, false, true);
    if (!pe) {
        return -2;
    }
    std::cout << "Loaded at: " <<std::hex << (ULONGLONG)pe << "\n";
    ULONGLONG found_base = peconv::find_base_candidate(pe, v_size);
    bool is_ok = false;
    if (found_base == (ULONGLONG)pe) {
        is_ok = true;
        std::cout << "[+] Success! Correct base found!\n";
    }
    std::cout << "Load Base: " << std::hex << (ULONGLONG)pe << "\n";

    peconv::free_pe_buffer(pe);
    std::cout << "Found Base: " << std::hex << found_base << "\n";
    return (is_ok) ? 0 : 1;
}
