#include "test_replacing_func.h"

#include "peconv.h"
using namespace peconv;

#include <iostream>
#include <string>
#include <map>


namespace test8 {
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

    VOID WINAPI my_Sleep(_In_ DWORD dwMilliseconds)
    {
        std::cout << "Sleeping: " << dwMilliseconds << std::endl;
    }

    VOID WINAPI my_ExitProcess(UINT exitCode)
    {
        std::cout << "my_ExitProcess: " << exitCode << std::endl;
        if (exitCode != 0) {
            std::cout << "Failed!" << std::endl;
        }
        ExitProcess(exitCode);
    }

    __int64 __fastcall my_calc_checksum64(__int64 a1, char a2)
    {
        std::cout << "This is my own function" << std::endl;
        return 0x1F561E6A;
    }

    int __cdecl my_calc_checksum32(const char *a1, char a2) //sub_402AB0
    {
        std::cout << "This is my own function" << std::endl;
        return 0x1F561E6A;
    }

};

int tests::replace_func_testcase(LPCTSTR path)
{

    if (path == NULL) {
        std::cerr << "Supply the path to the app" << std::endl;
        return -1;
    }
    std::cout << "Trying to load: " << path << std::endl;
    size_t v_size = 0;

    peconv::hooking_func_resolver my_res;
    my_res.add_hook("MessageBoxA", (FARPROC) &test8::my_MessageBoxA);
    my_res.add_hook("Sleep", (FARPROC) &test8::my_Sleep);
    my_res.add_hook("ExitProcess", (FARPROC)&test8::my_ExitProcess);
    BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, (peconv::t_function_resolver*) &my_res);

    if (!loaded_pe) {
        return -1;
    }
#ifndef _WIN64

    // replace the call target (it replaces the call address at the given offset)
    {
        ULONGLONG checksum_call_offset = (ULONGLONG)loaded_pe + 0x2A4C;
        ULONGLONG dest_addr = (ULONGLONG)&test8::my_calc_checksum32;
        if (!peconv::replace_target((BYTE*)checksum_call_offset, dest_addr)) {
            std::cout << "Failed replacing target!" << std::endl;
            peconv::free_pe_buffer(loaded_pe, v_size);
            return -1;
        }
    }

    //if the function was not redirected to local, we can still export and use the original one:
    {
        ULONGLONG checksum_func_offset = (ULONGLONG)loaded_pe + 0x2AB0;

        int(__cdecl *calc_checksum32)(const char *a1, BYTE a2) =
            (int(__cdecl *)(const char *, BYTE)) checksum_func_offset;

        DWORD checksum = calc_checksum32("my_test_password", true);
        if (checksum != 0x9e5619e7) {
            std::cout << "Wrong checksum" << std::endl;
            peconv::free_pe_buffer(loaded_pe, v_size);
            return -1;
        }
    }

#else
    //in case of 64bit binary we cannot replace the target, so we redirect the function to local
    ULONGLONG checksum_offset = (ULONGLONG)loaded_pe + 0x2B10;
    peconv::redirect_to_local64((BYTE*)checksum_offset, (ULONGLONG)&test8::my_calc_checksum64);
#endif
    ULONGLONG ep_exp_offset = (ULONGLONG) loaded_pe + peconv::get_entry_point_rva(loaded_pe);
    void (_cdecl *ep_func)() = (void (_cdecl *)()) (ep_exp_offset);
    std::cout << "Calling entry point:" <<std::endl;
    ep_func();
    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}
