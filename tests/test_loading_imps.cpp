#include <stdio.h>
#include <windows.h>

#include "test_loading_imps.h"

int tests::deploy_self_ex(peconv::t_function_resolver* func_resolver)
{
    char marker_path[] = "peconv_test_marker";
    DWORD current_pid = GetCurrentProcessId();

    printf("My PID: %d\n", current_pid);
    printf("My ptr: %p\n", &deploy_self_ex);

    char my_env[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableA(marker_path, my_env, MAX_PATH)) {
        int pid = atoi(my_env);
        if (pid == current_pid) {
            printf("Second iteration: marker found\n");
        }
        return 0;
    } else {
        printf("First iteration: marker not found\n");
    }

    TCHAR my_path[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, my_path, MAX_PATH);
    size_t v_size = 0;
    std::tcout << TEXT("Module: ") << my_path << std::endl;
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = peconv::load_pe_executable(my_path, v_size, func_resolver);
    ULONGLONG ep = peconv::get_entry_point_rva(loaded_pe) + (ULONGLONG) loaded_pe;
    LPVOID ep_ptr = (LPVOID) ep;

    // Deploy itself!
    // read the Entry Point from the headers:
    int (*loaded_pe_entry)(void);
    loaded_pe_entry = (int (*)(void)) ep_ptr;

    _itoa_s(current_pid, my_env, 10);
    if (SetEnvironmentVariableA(marker_path, my_env)) {
        printf ("Env marker set!\n");
    }

    //call the loaded PE's ep:
    printf("Calling the Entry Point of the loaded module:\n");
    int ret_val = loaded_pe_entry();
    return ret_val;
}

int tests::deploy_self()
{
    return tests::deploy_self_ex(NULL);
}
