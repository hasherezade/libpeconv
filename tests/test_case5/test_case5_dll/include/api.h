#pragma once

#ifdef DLL_EXPORTS
#define DLL_API __declspec(dllexport) __stdcall
#else
#define DLL_API __declspec(dllimport) __stdcall
#endif

int DLL_API test_checksum1();
int DLL_API test_checksum2();
int DLL_API test_checksum3();
int DLL_API test_checksum4();
int DLL_API test_checksum5();
