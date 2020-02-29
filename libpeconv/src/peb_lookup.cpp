#pragma once

#include <Windows.h>
#include "ntddk.h"

#include "peconv\peb_lookup.h"

//here we don't want to use any functions imported form extenal modules

typedef struct _LDR_MODULE { 
    LIST_ENTRY  InLoadOrderModuleList;//   +0x00 
    LIST_ENTRY  InMemoryOrderModuleList;// +0x08   
    LIST_ENTRY  InInitializationOrderModuleList;// +0x10 
    void*   BaseAddress; // +0x18 
    void*   EntryPoint;  // +0x1c 
    ULONG   SizeOfImage; 
    UNICODE_STRING FullDllName; 
    UNICODE_STRING BaseDllName; 
    ULONG   Flags; 
    SHORT   LoadCount; 
    SHORT   TlsIndex; 
    HANDLE  SectionHandle; 
    ULONG   CheckSum; 
    ULONG   TimeDateStamp; 
} LDR_MODULE, *PLDR_MODULE;

inline PPEB get_peb()
{
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
/*
//alternative way to fetch it:
    LPVOID PEB = NULL;
    __asm {
        mov eax, fs:[30h]
        mov PEB, eax
    };
    return (PPEB)PEB;
*/
#endif
}

inline PLDR_MODULE get_ldr_module()
{
    PPEB peb = get_peb();
    if (peb == NULL) {
        return NULL;
    }
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;
    
    PLDR_MODULE Flink = *( ( PLDR_MODULE * )( &list ) );
    return Flink;
}

inline WCHAR to_lowercase(WCHAR c1)
{
    if (c1 <= L'Z' && c1 >= L'A') {
        c1 = (c1 - L'A') + L'a';
    }
    return c1;
}

bool is_wanted_module(LPWSTR curr_name, LPWSTR wanted_name)
{
    if (wanted_name == NULL || curr_name == NULL) return false;

    WCHAR *curr_end_ptr = curr_name;
    while (*curr_end_ptr != L'\0') {
        curr_end_ptr++;
    }
    if (curr_end_ptr == curr_name) return false;

    WCHAR *wanted_end_ptr = wanted_name;
    while (*wanted_end_ptr != L'\0') {
        wanted_end_ptr++;
    }
    if (wanted_end_ptr == wanted_name) return false;

    while ((curr_end_ptr != curr_name) && (wanted_end_ptr != wanted_name)) {

        if (to_lowercase(*wanted_end_ptr) != to_lowercase(*curr_end_ptr)) {
            return false;
        }
        wanted_end_ptr--;
        curr_end_ptr--;
    }
    return true;
}

HMODULE peconv::get_module_via_peb(IN OPTIONAL LPWSTR module_name)
{
    PLDR_MODULE curr_module = get_ldr_module();
    if (!module_name) {
        return (HMODULE)(curr_module->BaseAddress);
    }
    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (is_wanted_module(curr_module->BaseDllName.Buffer, module_name)) {
            return (HMODULE)(curr_module->BaseAddress);
        }
        curr_module = (PLDR_MODULE) curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

size_t peconv::get_module_size_via_peb(IN OPTIONAL HMODULE hModule)
{
    PLDR_MODULE curr_module = get_ldr_module();
    if (!hModule) {
        return (size_t)(curr_module->SizeOfImage);
    }
    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (hModule == (HMODULE)(curr_module->BaseAddress)) {
            return (size_t)(curr_module->SizeOfImage);
        }
        curr_module = (PLDR_MODULE)curr_module->InLoadOrderModuleList.Flink;
    }
    return 0;
}
