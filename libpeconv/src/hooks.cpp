#include "peconv/hooks.h"
#include "peconv.h"
#include "peconv/peb_lookup.h"

using namespace peconv;

namespace peconv {

    bool is_pointer_in_ntdll(LPVOID lpAddress)
    {
        HMODULE mod = peconv::get_module_via_peb(L"ntdll.dll");
        size_t module_size = peconv::get_module_size_via_peb(mod);
        if (peconv::validate_ptr(mod, module_size, lpAddress, sizeof(BYTE))) {
            return true; //this address lies within NTDLL
        }
        return false;
    }

    BOOL nt_protect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
    {
        FARPROC proc = peconv::get_exported_func(
            peconv::get_module_via_peb(L"ntdll.dll"),
            "NtProtectVirtualMemory"
        );
        if (!proc) {
            return FALSE;
        }
        NTSTATUS(NTAPI *_NtProtectVirtualMemory)(
            IN HANDLE,
            IN OUT PVOID*,
            IN OUT PSIZE_T,
            IN DWORD,
            OUT PDWORD) =
            (NTSTATUS(NTAPI *)(
                IN HANDLE,
                IN OUT PVOID*,
                IN OUT PSIZE_T,
                IN DWORD,
                OUT PDWORD)) proc;

        SIZE_T protect_size = dwSize;
        NTSTATUS status = _NtProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &protect_size, flNewProtect, lpflOldProtect);
        if (status != S_OK) {
            return FALSE;
        }
        return TRUE;
    }
};

bool PatchBackup::makeBackup(BYTE *patch_ptr, size_t patch_size)
{
    if (!patch_ptr) {
        return false;
    }
    deleteBackup();
    this->sourcePtr = patch_ptr;
    this->buffer = new BYTE[patch_size];
    this->bufferSize = patch_size;

    memcpy(buffer, patch_ptr, patch_size);
    return true;
}

bool PatchBackup::applyBackup()
{
    if (!isBackup()) {
        return false;
    }
    DWORD oldProtect = 0;
    if (!nt_protect((LPVOID)sourcePtr, bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    memcpy(sourcePtr, buffer, bufferSize);
    nt_protect((LPVOID)sourcePtr, bufferSize, oldProtect, &oldProtect);

    //flush cache:
    FlushInstructionCache(GetCurrentProcess(), sourcePtr, bufferSize);
    return true;
}

FARPROC peconv::hooking_func_resolver::resolve_func(LPSTR lib_name, LPSTR func_name)
{
    //the name may be ordinal rather than string, so check if it is a valid pointer:
    if (!peconv::is_bad_read_ptr(func_name, 1)) {
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

size_t peconv::redirect_to_local64(void *ptr, ULONGLONG new_offset, PatchBackup* backup)
{
    if (!ptr) return 0;

    BYTE hook_64[] = {
        0x48, 0xB8, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xEE, 0xFF, //movabs rax,FFEE998877665544 
        0xFF, 0xE0 //jmp rax
    };
    const size_t hook64_size = sizeof(hook_64);
    if (is_pointer_in_ntdll(ptr)) {
        std::cout << "[WARNING] Patching NTDLL is not allowed because of possible stability issues!\n";
        return 0;
    }
    DWORD oldProtect = 0;
    if (!nt_protect((LPVOID)ptr,
        hook64_size,
        PAGE_EXECUTE_READWRITE, //this must be executable if we are hooking kernel32.dll, because we are using VirtualProtect from kernel32 at the same time
        &oldProtect))
    {
        return 0;
    }

    if (backup != nullptr) {
        backup->makeBackup((BYTE*)ptr, hook64_size);
    }
    memcpy(hook_64 + 2, &new_offset, sizeof(ULONGLONG));
    memcpy(ptr, hook_64, hook64_size);

    nt_protect((LPVOID)ptr, hook64_size, oldProtect, &oldProtect);

    //flush cache:
    FlushInstructionCache(GetCurrentProcess(), ptr, hook64_size);
    return hook64_size;
}

size_t peconv::redirect_to_local32(void *ptr, DWORD new_offset, PatchBackup* backup)
{
    if (!ptr) return 0;

    BYTE hook_32[] = {
        0xB8, 0xCC, 0xDD, 0xEE, 0xFF, // mov eax,FFEEDDCC
        0xFF, 0xE0 //jmp eax
    };
    const size_t hook32_size = sizeof(hook_32);
    if (is_pointer_in_ntdll(ptr)) {
        std::cout << "[WARNING] Patching NTDLL is not allowed because of possible stability issues!\n";
        return 0;
    }
    DWORD oldProtect = 0;
    if (!nt_protect((LPVOID)ptr,
        hook32_size,
        PAGE_EXECUTE_READWRITE, //this must be executable if we are hooking kernel32.dll, because we are using VirtualProtect from kernel32 at the same time
        &oldProtect))
    {
        return 0;
    }

    if (backup != nullptr) {
        backup->makeBackup((BYTE*)ptr, hook32_size);
    }
    memcpy(hook_32 + 1, &new_offset, sizeof(DWORD));
    memcpy(ptr, hook_32, hook32_size);

    nt_protect((LPVOID)ptr, hook32_size, oldProtect, &oldProtect);

    //flush cache:
    FlushInstructionCache(GetCurrentProcess(), ptr, hook32_size);
    return hook32_size;
}

size_t peconv::redirect_to_local(void *ptr, void* new_function_ptr, PatchBackup* backup)
{
#ifdef _WIN64
    return peconv::redirect_to_local64(ptr, (ULONGLONG)new_function_ptr, backup);
#else
    return peconv::redirect_to_local32(ptr, (DWORD)new_function_ptr, backup);
#endif
}

inline long long int get_jmp_delta(ULONGLONG currVA, int instrLen, ULONGLONG destVA)
{
    long long int diff = destVA - (currVA + instrLen);
    return diff;
}

inline bool is_valid_delta(long long int delta)
{
    DWORD first_dw = delta >> sizeof(DWORD) * 8;
    if (first_dw == 0) {
        return true;
    }
    const DWORD max_dword = DWORD(-1);
    if (first_dw != max_dword) {
        return false;
    }
    DWORD delta_dw = DWORD(delta);
    if (delta_dw & 0x80000000) {
        return true;
    }
    //invalid, sign bit is missing
    return false;
}

bool peconv::replace_target(BYTE *patch_ptr, ULONGLONG dest_addr)
{
    typedef enum {
        OP_JMP = 0xE9,
        OP_CALL_DWORD = 0xE8
    } t_opcode;

    if (patch_ptr[0] == OP_JMP || patch_ptr[0] == OP_CALL_DWORD) {
        ULONGLONG delta = get_jmp_delta(ULONGLONG(patch_ptr), 5, dest_addr);
        if (!is_valid_delta(delta)) {
#ifdef _DEBUG
            std::cout << "Cannot replace the target: too big delta: " << std::hex << delta << std::endl;
#endif
            //too big delta, cannot be saved in a DWORD
            return false;
        }
        DWORD delta_dw = DWORD(delta);
        memcpy(patch_ptr + 1, &delta_dw, sizeof(DWORD));

        //flush cache:
        FlushInstructionCache(GetCurrentProcess(), patch_ptr + 1, sizeof(DWORD));
        return true;
    }
    return false;
}
