#include "ntddk.h"
#include <peconv/util.h>
#include <peconv/peb_lookup.h>

class SectionLocker {
public:
    SectionLocker(RTL_CRITICAL_SECTION &_section)
        : section(_section)
    {
        RtlEnterCriticalSection(&section);
    }

    ~SectionLocker()
    {
        RtlLeaveCriticalSection(&section);
    }

protected:
    RTL_CRITICAL_SECTION &section;
};

//here we don't want to use any functions imported form extenal modules
namespace {
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
#if defined(_M_AMD64)
        return (PPEB)__readgsqword(0x60);
#elif defined(_M_ARM64)
        const PPEB peb = (PPEB)(*(__getReg(18) + 0x60));
        return peb;
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

        or:
        LPVOID PEB = RtlGetCurrentPeb();
    */
#endif
    }

    inline LPCWSTR find_string_end(LPCWSTR str)
    {
        if (!str) return nullptr;

        LPCWSTR curr_end_ptr = str;
        while (*curr_end_ptr != L'\0') {
            curr_end_ptr++;
        }
        return curr_end_ptr;
    }
};

bool is_wanted_module(LPCWSTR curr_name, LPCWSTR wanted_name)
{
    if (wanted_name == NULL || curr_name == NULL) return false;

    LPCWSTR curr_end_ptr = find_string_end(curr_name);
    if (curr_end_ptr == curr_name) return false;

    LPCWSTR wanted_end_ptr = find_string_end(wanted_name);
    if (wanted_end_ptr == wanted_name) return false;

    // iterate from the last character towards the beginning
    while (true) {
        if (peconv::to_lowercase(*wanted_end_ptr) != peconv::to_lowercase(*curr_end_ptr)) {
            return false;
        }
        // if any of the string reached its beginning:
        if (wanted_end_ptr == wanted_name || curr_end_ptr == curr_name) {
            break;
        }
        wanted_end_ptr--;
        curr_end_ptr--;
    }
    // can be true only if the entire wanted_name was consumed
    if (wanted_end_ptr == wanted_name) {
        if (curr_end_ptr == curr_name) return true;
        curr_end_ptr--;
        if ((*curr_end_ptr) == L'\\' || (*curr_end_ptr) == L'/') return true;
    }
    return false;
}

HMODULE peconv::get_module_via_peb(IN OPTIONAL LPCWSTR module_name)
{
    const PPEB peb = get_peb();
    if (!peb || !peb->Ldr || !peb->LoaderLock) {
        return NULL;
    }
    SectionLocker locker(*peb->LoaderLock);

    const PLIST_ENTRY list_head = &peb->Ldr->InLoadOrderModuleList;
    PLDR_MODULE curr_module = (PLDR_MODULE)list_head->Flink;
    if (!module_name) {
        return (HMODULE)(curr_module->BaseAddress);
    }

    // it is a cyclic list, so if the next record links to the initial one, it means we went throught the full loop
    do {
        // this should also work as a terminator, because the BaseAddress of the last module in the cycle is NULL
        if (curr_module == NULL || curr_module->BaseAddress == NULL) {
            break;
        }
        if (is_wanted_module(curr_module->BaseDllName.Buffer, module_name)) {
            return (HMODULE)(curr_module->BaseAddress);
        }
        curr_module = (PLDR_MODULE)curr_module->InLoadOrderModuleList.Flink;

    } while ((PLIST_ENTRY)curr_module != list_head);

    return NULL;
}

size_t peconv::get_module_size_via_peb(IN OPTIONAL HMODULE hModule)
{
    const PPEB peb = get_peb();
    if (!peb || !peb->Ldr || !peb->LoaderLock) {
        return 0;
    }
    SectionLocker locker(*peb->LoaderLock);
    const PLIST_ENTRY list_head = &peb->Ldr->InLoadOrderModuleList;
    PLDR_MODULE curr_module = (PLDR_MODULE)list_head->Flink;
    if (!hModule) {
        return (size_t)(curr_module->SizeOfImage);
    }

    // it is a cyclic list, so if the next record links to the initial one, it means we went throught the full loop
    do {
        // this should also work as a terminator, because the BaseAddress of the last module in the cycle is NULL
        if (curr_module == NULL || curr_module->BaseAddress == NULL) {
            break;
        }
        if (hModule == (HMODULE)(curr_module->BaseAddress)) {
            return (size_t)(curr_module->SizeOfImage);
        }
        curr_module = (PLDR_MODULE)curr_module->InLoadOrderModuleList.Flink;

    } while ((PLIST_ENTRY)curr_module != list_head);

    return 0;
}

bool peconv::set_main_module_in_peb(HMODULE module_ptr)
{
    PPEB peb = get_peb();
    if (peb == NULL) {
        return false;
    }
    SectionLocker locker(*peb->FastPebLock);
    peb->ImageBaseAddress = module_ptr;
    return true;
}

HMODULE peconv::get_main_module_via_peb()
{
    PPEB peb = get_peb();
    if (peb == NULL) {
        return NULL;
    }
    SectionLocker locker(*peb->FastPebLock);
    return (HMODULE) peb->ImageBaseAddress;
}
