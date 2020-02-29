#include "test_peb_lookup.h"

#include <peconv.h>

namespace tests {

    int compare_modules_and_sizes(wchar_t* module_name = NULL)
    {
        std::wcout << "\n[*] Test: ";
        if (module_name == NULL) {
            std::wcout << "self";
        }
        else {
            std::wcout << module_name;
            LoadLibraryW(module_name);
        }
        std::wcout << "\n";
        HMODULE mod1 = peconv::get_module_via_peb(module_name);
        HMODULE mod2 = GetModuleHandleW(module_name);
        std::cout << "get_module_via_peb: " << std::hex << mod1 << "\n";
        std::cout << "GetModuleHandleA: " << std::hex << mod2 << "\n";
        if (mod1 != mod2) {
            return false;
        }

        size_t size1 = peconv::get_image_size((BYTE*)mod1);
        size_t size2 = peconv::get_module_size_via_peb(mod2);
        std::cout << "get_image_size: " << std::hex << size1 << "\n";
        std::cout << "get_module_size_via_peb: " << std::hex << size2 << "\n";
        if (size1 != size2) {
            return false;
        }
        return true;
    }
};

int tests::check_modules()
{
    if (!compare_modules_and_sizes(NULL)) {
        return 1;
    }
    if (!compare_modules_and_sizes(L"ntdll.dll")) {
        return 1;
    }
    if (!compare_modules_and_sizes(L"kernel32.dll")) {
        return 1;
    }
    if (!compare_modules_and_sizes(L"user32.dll")) {
        return 1;
    }
    if (!compare_modules_and_sizes(L"advapi32.dll")) {
        return 1;
    }
    if (!compare_modules_and_sizes(L"ws2_32.dll")) {
        return 1;
    }
    return 0;
}
