#include "test_crackme_f4_6.h"

#include "peconv.h"
#include "file_helper.h"

#include <iostream>

namespace test6 {

    DWORD (_fastcall *imported_func_1)(ULONGLONG a1) = NULL;
    DWORD (*display_chunk)(int, int, LPSTR a1) = NULL;

    const size_t g_flagLen = 26;
    char g_flagBuf[g_flagLen + 1] = { 0 };

    VOID
    WINAPI
    my_GetSystemTime(
        _Out_ LPSYSTEMTIME lpSystemTime
        )
    {
        static DWORD next_val = 0;
        GetSystemTime(lpSystemTime);
        lpSystemTime->wMonth = next_val;
        next_val++;
    }

    int _stdcall my_MessageBoxA(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType)
    {
        BYTE key_part = 0;
        int key_id = 0;
        sscanf(lpText,"key[%d] = %x;", &key_id, &key_part);
        g_flagBuf[key_id % g_flagLen] = key_part;
        return 0;
    }

    bool load_next_char(const char *path)
    {
#ifndef _WIN64
        printf("Compile the loader as 64bit!\n");
        system("pause");
      return 0;
#endif
        size_t v_size = 0;
        peconv::hooking_func_resolver my_res;
        my_res.add_hook("GetSystemTime", (FARPROC) &test6::my_GetSystemTime);
        my_res.add_hook("MessageBoxA", (FARPROC) &test6::my_MessageBoxA);
        BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, (peconv::t_function_resolver*) &my_res);
        if (!loaded_pe) {
          return false;
        }

        ULONGLONG modifying_func_offset = 0x5d30 + (ULONGLONG) loaded_pe;

        //hook local func:
        ULONGLONG srand_offset = 0x7900 + (ULONGLONG) loaded_pe;
        ULONGLONG rand_offset = 0x78D4 + (ULONGLONG) loaded_pe;

        peconv::redirect_to_local64((void*)srand_offset, ULONGLONG(&srand));
        peconv::redirect_to_local64((void*)rand_offset, ULONGLONG(&rand));

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
            std::cout << names_set[0] << std::endl;
#endif
            const char *got_name = names_set[0].c_str();
            FARPROC exp1 = peconv::get_exported_func(loaded_pe, const_cast<char*>(got_name));
            test6::display_chunk = (DWORD (*)(int, int, LPSTR) ) exp1;
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
        if (!test6::load_next_char(path)) {
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
