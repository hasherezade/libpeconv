#include "peconv\hooks.h"

using namespace peconv;

FARPROC peconv::hooking_func_resolver::resolve_func(LPSTR lib_name, LPSTR func_name)
{
    //the name may be ordinal rather than string, so check if it is a valid pointer:
    if (!IsBadReadPtr(func_name, 1)) {
        std::map<std::string, FARPROC>::iterator itr = hooks_map.find(func_name);
        if (itr != hooks_map.end()) {
            FARPROC hook = itr->second;
#ifdef _DEBUG
            std::cout << ">>>>>>Replacing: " << func_name << " by: " << hook << std::endl;
#endif
            return hook;
        }
    }
    return peconv::default_func_resolver::resolve_func(lib_name, func_name);
}

void peconv::redirect_to_local64(void *ptr, ULONGLONG new_offset)
{
    BYTE hook_64[] = {
        0x48, 0xB8, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xEE, 0xFF, //movabs rax,FFEE998877665544 
        0xFF, 0xE0 //jmp rax
    }; 

    memcpy(hook_64 + 2, &new_offset, sizeof(ULONGLONG));
    memcpy(ptr, hook_64, sizeof(hook_64));
}

void peconv::redirect_to_local32(void *ptr, DWORD new_offset)
{
    BYTE hook_32[] = {
        0xB8, 0xCC, 0xDD, 0xEE, 0xFF, // mov eax,FFEEDDCC
        0xFF, 0xE0 //jmp eax
    };
    memcpy(hook_32 + 1, &new_offset, sizeof(DWORD));
    memcpy(ptr, hook_32, sizeof(hook_32));
}
