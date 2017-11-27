#include "test_hooking_imps.h"

#include "peconv.h"

#include <iostream>

int _stdcall my_MessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType)
{
    std::cout << "TITLE: [" << lpCaption << "]" << std::endl;
    std::cout << "MESSAGE: [" << lpText << "]" <<std::endl;
    return 1337;
}

int _stdcall my_MessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    std::wcout << L"TITLE: [" << lpCaption << L"]" << std::endl;
    std::wcout << L"MESSAGE: [" << lpText << L"]" <<std::endl;
    return 1338;
}

FARPROC my_func_resolver(LPSTR lib_name, LPSTR func_name)
{
    //the name may be ordinal rather than string, so check if it is a valid pointer:
    if (!IsBadReadPtr(func_name, 1)) {
        if (strcmp("MessageBoxA", func_name) == 0) {
            printf(">>>>>>Replacing MessageBoxA!\n");
            return (FARPROC) &my_MessageBoxA;
        }
        if (strcmp("MessageBoxW", func_name) == 0) {
            printf(">>>>>>Replacing MessageBoxW!\n");
            return (FARPROC) &my_MessageBoxW;
        }
    }
    return peconv::default_func_resolver(lib_name, func_name);
}

int tests::hook_testcase(char *path)
{
    if (path == NULL) {
        std::cerr << "Supply the path to the app" << std::endl;
        return -1;
    }
    std::cout << "Trying to load: " << path << std::endl;
    size_t v_size = 0;
    BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, my_func_resolver);
    if (!loaded_pe) {
        return -1;
    }

    ULONGLONG ep_exp_offset = (ULONGLONG) loaded_pe + peconv::get_entry_point_rva(loaded_pe);
    DWORD (*imported_func)() = (DWORD (*)()) (ep_exp_offset);
    
    std::cout << "Calling imported function:" <<std::endl;
    imported_func();
    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}
