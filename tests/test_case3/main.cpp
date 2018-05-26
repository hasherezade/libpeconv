#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "checksum.h"

bool get_rand_string(char *buffer, size_t buffer_size)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUWVXYZabcdefghijklmnopqrstuwvxyz1234567890";
    size_t charset_len = strlen(charset);

    srand(GetTickCount());
    for (size_t i = 0; i < buffer_size - 1; i++) {
        size_t c_indx = rand() % charset_len;
        buffer[i] = charset[c_indx];
        Sleep(1000);
    }
    buffer[buffer_size - 1] = '\0';
    return true;
}

bool is_password_valid(char *str)
{
    DWORD checksum = calc_checksum(str, true);
    if (checksum == 0x1f561e6a) { //calc_checksum("my_demo_password", true);
        return true;
    }
    return false;
}

int main()
{
    char str[14] = { 0 };
    get_rand_string(str, 12);

    std::cout << str << std::endl;

    if (is_password_valid(str)) {
        MessageBoxA(NULL, "Passed!", "Test Case 3", MB_OK);
    } else {
        std::cout << "Failed!" << std::endl;
        MessageBoxA(NULL, "Failed!", "Test Case 3", MB_OK);
    }

    return 0;
}
