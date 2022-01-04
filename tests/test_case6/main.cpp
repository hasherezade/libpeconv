#include <windows.h>
#include <string>
#include <iostream>

#include "callback.h"

std::string get_pass()
{
    std::string result = "";
    while (g_pass_mutex == nullptr) {
        Sleep(10);
    }
    g_pass_mutex = CreateMutexA(NULL, FALSE, NULL);
    WaitForSingleObject(g_pass_mutex, INFINITE);
    result = g_Pass;
    ReleaseMutex(g_pass_mutex);
    return result;
}

int main()
{
    std::cout << "Test case 6: Entry Point called!" << std::endl;
    std::cout << "Password: " << get_pass() << std::endl;
    return 0;
}
