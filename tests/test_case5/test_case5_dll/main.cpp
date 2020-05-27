#include <Windows.h>
#include <iostream>

#define DLL_EXPORTS
#include "api.h"

inline DWORD rotl32a(DWORD x, DWORD n)
{
    return (x << n) | (x >> (32 - n));
}

inline char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        c = c - 'A' + 'a';
    }
    return c;
}

DWORD calc_checksum(BYTE *str, size_t buf_size, bool enable_tolower)
{
    if (str == NULL) return 0;

    DWORD checksum = 0;
    for (size_t i = 0; i < buf_size; i++) {
        checksum = rotl32a(checksum, 7);
        char c = str[i];
        if (enable_tolower) {
            c = to_lower(c);
        }
        checksum ^= c;
    }
    return checksum;
}

int DLL_API test_checksum1()
{
    char test1[] = "this is a test!";
    DWORD checks = calc_checksum((BYTE*)test1, strlen(test1), true);
    std::cout << "Checks 1: " << std::hex << checks << std::endl;
    return checks;
}

int DLL_API test_checksum2()
{
    wchar_t teststr[] = L"Checking wide strings";
    DWORD checks = calc_checksum((BYTE*)teststr, sizeof(teststr), true);
    MessageBoxW(NULL, teststr, L"Test Case 5", MB_OK);
    std::cout << "Checks 2: " << std::hex << checks << std::endl;
    return checks;
}

int DLL_API test_checksum4()
{
    wchar_t teststr[] = L"Test checksum 4";
    DWORD checks = calc_checksum((BYTE*)teststr, sizeof(teststr), true);
    MessageBoxW(NULL, teststr, L"Test Case 5", MB_OK);
    std::cout << "Checks 4: " << std::hex << checks << std::endl;
    return checks;
}

int DLL_API test_checksum5()
{
    wchar_t teststr[] = L"Yet another checksum test: 5";
    DWORD checks = calc_checksum((BYTE*)teststr, sizeof(teststr), true);
    MessageBoxW(NULL, teststr, L"Test Case 5", MB_OK);
    std::cout << "Checks 5: " << std::hex << checks << std::endl;
    return checks;
}

int DLL_API test_checksum3()
{
    SYSTEMTIME SystemTime;
    GetSystemTime(&SystemTime);

    TCHAR pszDate[200];
    GetDateFormatA(LOCALE_USER_DEFAULT, DATE_LONGDATE, &SystemTime, NULL, pszDate, 200);

    wchar_t teststr[] = L"Time func checksum";
    DWORD checks = calc_checksum((BYTE*)teststr, sizeof(teststr), true);
    std::cout << "Checks 3: " << std::hex << checks << std::endl;
    MessageBoxA(NULL, pszDate, "Test Case 5", MB_OK);
    return checks;
}

BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        printf("Test Case 5 DLL loaded\n");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
