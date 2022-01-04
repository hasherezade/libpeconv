/**
Example based on: White Rabbit crackme, stage 2
more info: https://hshrzd.wordpress.com/2018/02/03/white-rabbit-crackme/
*/
#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include "main.h"

//#define TEST_WITH_SOCKETS - for manual tests

#ifdef TEST_WITH_SOCKETS
    #include "sockets.h"
#endif

char junk_buf[0x100] = { 0 };

inline int junk_code() {
    srand(GetTickCount());
    for (int i = 0; i < 10; i++) {
        junk_buf[i] = rand();
    }
    return rand();
}

bool check_condition(char buf[10], int number)
{
#ifdef TEST_WITH_SOCKETS
    return listen_for_connect(buf, number);
#else
    switch (buf[0]) {
    case 0:
        buf[0] = '9'; break;
    case '9':
        buf[0] = '3'; break;
    case '3':
        buf[0] = '5'; break;
    default:
        buf[0] = 0;
    }
    return true;
#endif
}

void NTAPI tls_callback1(PVOID DllHandle, DWORD dwReason, PVOID arg)
{
    std::cout << __FUNCTION__ << ": TLS callback: dwReason: " << dwReason << "\n";
    size_t pos = junk_code();
    char pass[100] = { 0 };
    junk_code();
    if (strnlen(g_Pass, sizeof(g_Pass)) >= 10) return;
    size_t indx = 0;
    size_t indx2 = 1;
    char buf[10] = { 0 };
    //"NR7YcqGFUn0";
    if (check_condition(buf, 1337)) {
        pass[indx] = 0x87 - buf[0];
        indx += 2;
        pass[indx2] = 0x8b - buf[0];
        indx2 += 2;
        pass[indx] = 0x70 - buf[0];
        indx += 2;
        pass[indx] = 0x9c - buf[0];
        indx += 2;
    }

    junk_code();
    junk_code();
    junk_code();
    if (check_condition(buf, 1338)) {
        pass[indx2] = 0x8c - buf[0];
        indx2 += 2;
        pass[indx2] = 0xa4 - buf[0]; //'q'
        indx2 += 2;
        pass[indx] = 0x7a - buf[0]; //'G'
        indx += 2;
    }

    junk_code();
    if (check_condition(buf, 1339)) { //"FUn0"
        pass[8] = 0x8a - buf[0]; //'U'
        junk_code();
        pass[7] = 0x7b - buf[0]; //'F'
        pass[10] = 0x65 - buf[0]; // '0'
        junk_code();
        pass[9] = 0xa3 - buf[0]; //'n'
    }

    g_pass_mutex = CreateMutexA(NULL, TRUE, NULL);
    WaitForSingleObject(g_pass_mutex, INFINITE);
    //copy to global:
    memcpy(g_Pass, pass, 10);
    ReleaseMutex(g_pass_mutex);

    std::cout << __FUNCTION__ << ": TLS callback: finished\n";
}

void NTAPI tls_callback2(PVOID DllHandle, DWORD dwReason, PVOID arg)
{
    std::cout << __FUNCTION__ << ": TLS callback: dwReason: " << dwReason << "\n";
    std::cout << __FUNCTION__ << ": TLS callback: finished\n";
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func1")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func1")
#endif

#ifdef _WIN64
#pragma const_seg(".CRT$XLF")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLF")
EXTERN_C
#endif
PIMAGE_TLS_CALLBACK tls_callback_func1 = tls_callback1;
PIMAGE_TLS_CALLBACK tls_callback_func2 = tls_callback2;
#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64
