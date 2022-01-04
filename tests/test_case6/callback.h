#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include "main.h"

void NTAPI tls_callback1(PVOID DllHandle, DWORD dwReason, PVOID arg)
{
    MessageBoxA(NULL, "TLS callback executed!", "Test Case 6", MB_OK);
    std::cout << "TLS callback 1: dwReason: " << dwReason << "\n";
}

void NTAPI tls_callback2(PVOID DllHandle, DWORD dwReason, PVOID arg)
{
    MessageBoxA(NULL, "Another TLS callback!", "Test Case 6", MB_OK);
    std::cout << "TLS callback 2: dwReason: " << dwReason << "\n";
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
