#include "test_hooking_imps.h"

#include "peconv.h"
using namespace peconv;

#include <iostream>
#include <string>
#include <map>

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

int tests::hook_testcase(char *path)
{
    if (path == NULL) {
        std::cerr << "Supply the path to the app" << std::endl;
        return -1;
    }
    std::cout << "Trying to load: " << path << std::endl;
    size_t v_size = 0;


    peconv::hooking_func_resolver my_res;
    my_res.add_hook("MessageBoxA", (FARPROC) &my_MessageBoxA);
    my_res.add_hook("MessageBoxW", (FARPROC) &my_MessageBoxW);
    BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, (peconv::t_function_resolver*) &my_res);

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
