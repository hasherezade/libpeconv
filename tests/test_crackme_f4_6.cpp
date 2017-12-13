#include "test_crackme_f4_6.h"

#include "peconv.h"
#include "file_helper.h"

#include <iostream>

namespace test6 {

    DWORD (_fastcall *imported_func_1)(ULONGLONG a1) = NULL;
    DWORD (*display_chunk)(int, int, LPSTR a1) = NULL;

    const size_t g_flagLen = 26;
    char g_flagBuf[g_flagLen + 1] = { 0 };

    int
    WINAPI
    my_MessageBoxA(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType)
    {
        static int key_id = 0;
        std::string str = lpText;

        std::size_t pos = str.find("0x");
        std::string str3 = str.substr(pos);
        unsigned char key_part = std::stoul(str3, nullptr, 16);

        g_flagBuf[(key_id++) % g_flagLen] = key_part;
        return 0;
    }

    int my_index()
    {
        static int index = 0;
        return (index++) % g_flagLen;
    }

    bool load_next_char(const char *path)
    {
        size_t v_size = 0;
        peconv::hooking_func_resolver my_res;
        my_res.add_hook("MessageBoxA", (FARPROC) &test6::my_MessageBoxA);
        BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, (peconv::t_function_resolver*) &my_res);
        if (!loaded_pe) {
            printf("Cannot load PE\n");
            return false;
        }

        ULONGLONG modifying_func_offset = 0x5d30 + (ULONGLONG) loaded_pe;

        //hook local func:
        ULONGLONG srand_offset = (ULONGLONG)loaded_pe + 0x7900;
        ULONGLONG rand_offset = (ULONGLONG)loaded_pe + 0x78D4;
        ULONGLONG calc_index_offset = (ULONGLONG)loaded_pe + 0x4710;

        peconv::redirect_to_local64((void*)srand_offset, ULONGLONG(&srand));
        peconv::redirect_to_local64((void*)rand_offset, ULONGLONG(&rand));
        peconv::redirect_to_local64((void*)calc_index_offset, (ULONGLONG)&my_index);

        test6::imported_func_1 = (DWORD (_fastcall *)(ULONGLONG)) (modifying_func_offset); 
#ifdef _DEBUG
        printf("Calling the main func:\n");
#endif
        DWORD returned = test6::imported_func_1((ULONGLONG)loaded_pe);
#ifdef _DEBUG
        printf("Returned: %x\n", returned);
#endif
        std::vector<std::string> names_set;
        if (peconv::get_exported_names(loaded_pe,names_set) > 0) {
#ifdef _DEBUG
            std::cout << "exported: " << names_set[0] << std::endl;
#endif
            const char *got_name = names_set[0].c_str();
            FARPROC exp1 = peconv::get_exported_func(loaded_pe, const_cast<char*>(got_name));
            test6::display_chunk = (DWORD (*)(int, int, LPSTR) ) exp1;
            printf("Calling exported function at: %p\n", exp1);
            test6::display_chunk(0, 0, const_cast<char*>(got_name));
        }
        peconv::free_pe_buffer(loaded_pe, v_size);
        return true;
    }
}; //namespace test6

//For now this is for manual tests only:
int tests::decode_crackme_f4_6(char *path)
{
#ifndef _WIN64
    printf("Compile the loader as 64bit!\n");
    return 0;
#endif
    char default_path[] = "C:\\tests\\payload.dll";
    if (!path) {
        path = default_path;
    }
    for (int i = 0; i < test6::g_flagLen; i++) {
        printf("Trying to load chunk: %d\n", i);
        if (!test6::load_next_char(path)) {
            printf("Cannot load next char...\n");
            return -1;
        }
    }
    printf("%s\n", test6::g_flagBuf);
    if (strcmp(test6::g_flagBuf, "wuuut-exp0rts@flare-on.com") != 0) {
        printf("Invalid flag!\n");
        return -1;
    }
    return 0;
}
