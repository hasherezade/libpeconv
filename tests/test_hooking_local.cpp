#include "test_hooking_local.h"

#include <peconv.h>
using namespace peconv;

#include <iostream>
#include <string>
#include <map>

#define FAKE_NAME "fake_module_name"

namespace test11 {
    int _stdcall my_MessageBoxA(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType)
    {
        std::cout << "TITLE: [" << lpCaption << "]" << std::endl;
        std::cout << "MESSAGE: [" << lpText << "]" << std::endl;
        return 1337;
    }

    int _stdcall my_MessageBoxW(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType)
    {
        std::wcout << L"TITLE: [" << lpCaption << L"]" << std::endl;
        std::wcout << L"MESSAGE: [" << lpText << L"]" << std::endl;
        return 1338;
    }

    int __cdecl my_rand(void)
    {
        return 44;
    }

    DWORD
    WINAPI
        my_GetModuleFileNameA(
            IN OPTIONAL HMODULE hModule,
            OUT LPSTR lpFilename,
            IN DWORD nSize
        )
    {
        const char fake_name[] = FAKE_NAME;
        size_t to_copy = strlen(fake_name);
        if (to_copy < nSize) to_copy = nSize;

        memcpy(lpFilename, fake_name, to_copy);
        return to_copy;
    }
};

int tests::hook_self_local()
{
    char normal_name[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, normal_name, MAX_PATH);

    HMODULE user32_lib = LoadLibraryA("user32.dll");
    HMODULE kernel32_lib = LoadLibraryA("kernel32.dll");
    FARPROC proc = GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
    PatchBackup backup;


    peconv::redirect_to_local(GetProcAddress(user32_lib, "MessageBoxA"), &test11::my_MessageBoxA);
    peconv::redirect_to_local(GetProcAddress(kernel32_lib, "GetModuleFileNameA"), &test11::my_GetModuleFileNameA, &backup);
    peconv::redirect_to_local(rand, &test11::my_rand);

    char module_name[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, module_name, MAX_PATH);
    MessageBoxA(0, module_name, "Module Name", MB_OK);

    if (strcmp(FAKE_NAME, module_name) != 0) {
        std::cout << "Failed!";
        return -1;
    }
    srand(10000);
    int rand_val = rand();
    if (rand_val != 44) {
        std::cout << "Failed: " << rand_val << "\n";
        return -2;
    }
    if (!backup.applyBackup()) {
        std::cout << "Failed! Cannot apply backup.";
        return -3;
    }
    GetModuleFileNameA(NULL, module_name, MAX_PATH);
    MessageBoxA(0, module_name, "Module Name", MB_OK);

    if (strcmp(normal_name, module_name) != 0) {
        std::cout << "Failed!";
        return -4;
    }
    return 0;
}
