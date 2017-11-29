#include "test_crackme_f4_6.h"

#include "peconv.h"
#include "file_helper.h"

#include <iostream>

namespace test6 {

    DWORD (_fastcall *imported_func_1)(ULONGLONG a1) = NULL;
    DWORD (*display_chunk)(int, int, LPSTR a1) = NULL;

    VOID
    WINAPI
    my_GetSystemTime(
        _Out_ LPSYSTEMTIME lpSystemTime
        )
    {
        static DWORD next_val = 11;
        GetSystemTime(lpSystemTime);
        lpSystemTime->wMonth = next_val;
        next_val++;
    }

    void __cdecl my_srand(unsigned int seed)
    {
        return srand(seed);
    }

    int __cdecl my_rand()
    {
        int rval = rand();
        return rval;
    }

    int _stdcall my_MessageBoxA(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType)
    {
        BYTE key_part = 0;
        sscanf(lpText,"%*s = %x;",&key_part);
        printf("%c", key_part);
        return 1337;
    }

    char load_next_char()
    {
#ifndef _WIN64
        printf("Compile the loader as 64bit!\n");
        system("pause");
      return 0;
#endif
        char default_path[] = "C:\\FlareOn2017\\payload.dll";
        char *path = default_path;

        size_t v_size = 0;
        peconv::hooking_func_resolver my_res;
        my_res.add_hook("GetSystemTime", (FARPROC) &test6::my_GetSystemTime);
        my_res.add_hook("MessageBoxA", (FARPROC) &test6::my_MessageBoxA);
        BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, (peconv::t_function_resolver*) &my_res);
        if (!loaded_pe) {
          return -1;
        }

        ULONGLONG modifying_func_offset = 0x5d30 + (ULONGLONG) loaded_pe;

        //hook local func:
        ULONGLONG srand_offset = 0x7900 + (ULONGLONG) loaded_pe;
        ULONGLONG rand_offset = 0x78D4 + (ULONGLONG) loaded_pe;

        peconv::redirect_to_local64((void*)srand_offset, ULONGLONG(&test6::my_srand));
        peconv::redirect_to_local64((void*)rand_offset, ULONGLONG(&test6::my_rand));

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
    }
}; //namespace test6

//For now this is for manual tests only:
int tests::decode_crackme_f4_6()
{
    for (int i = 0; i < 26; i++) {
        test6::load_next_char();
    }
    printf("\n");
    return 0;
}
