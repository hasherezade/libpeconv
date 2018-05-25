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

size_t peconv::redirect_to_local64(void *ptr, ULONGLONG new_offset)
{
    if (!ptr) return 0;

    BYTE hook_64[] = {
        0x48, 0xB8, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xEE, 0xFF, //movabs rax,FFEE998877665544 
        0xFF, 0xE0 //jmp rax
    }; 
    const size_t hook64_size = sizeof(hook_64);
    memcpy(hook_64 + 2, &new_offset, sizeof(ULONGLONG));
    memcpy(ptr, hook_64, hook64_size);
    return hook64_size;
}

size_t peconv::redirect_to_local32(void *ptr, DWORD new_offset)
{
    if (!ptr) return 0;

    BYTE hook_32[] = {
        0xB8, 0xCC, 0xDD, 0xEE, 0xFF, // mov eax,FFEEDDCC
        0xFF, 0xE0 //jmp eax
    };
    const size_t hook32_size = sizeof(hook_32);
    memcpy(hook_32 + 1, &new_offset, sizeof(DWORD));
    memcpy(ptr, hook_32, hook32_size);
    return hook32_size;
}

inline long long int get_jmp_delta(ULONGLONG currVA, int instrLen, ULONGLONG destVA)
{
    long long int diff = destVA - (currVA + instrLen);
    return diff;
}

bool peconv::replace_target(BYTE *patch_ptr, ULONGLONG dest_addr)
{
    typedef enum {
        OP_JMP = 0xE9,
        OP_CALL_DWORD = 0xE8
    } t_opcode;

    if (patch_ptr[0] == OP_JMP || patch_ptr[0] == OP_CALL_DWORD) {
        ULONGLONG delta = get_jmp_delta(ULONGLONG(patch_ptr), 5, dest_addr);
        const DWORD dword_max = DWORD(-1);
        if (delta > dword_max) {
            //too big delta, cannot be saved in a DWORD
            return false;
        }
        DWORD delta_dw = DWORD(delta);
        memcpy(patch_ptr + 1, &delta_dw, sizeof(DWORD));
        return true;
    }
    return false;
}
