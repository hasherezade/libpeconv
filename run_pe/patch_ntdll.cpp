#include "patch_ntdll.h"
#include <peconv.h>

template <typename ADDR_T>
inline ADDR_T calcJmpAddr(ADDR_T target, ADDR_T current_va, ADDR_T jmp_len = 5)
{
    return target - (current_va + jmp_len);
}

bool apply_ntdll_patch32(HANDLE hProcess, LPVOID module_ptr)
{
#ifndef _WIN64
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) return false; // should never happen

    const SIZE_T pos = 1;
    const SIZE_T stub_size = 0x16;

    ULONG_PTR _ZwQueryVirtualMemory = (ULONG_PTR)GetProcAddress(hNtdll, "ZwQueryVirtualMemory");
    if (!_ZwQueryVirtualMemory || _ZwQueryVirtualMemory < pos) {
        return false;
    }
    ULONG_PTR stub_ptr = (ULONG_PTR)_ZwQueryVirtualMemory - pos;
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    LPVOID patch_space = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!patch_space) {
        return false;
    }
    BYTE stub_buffer_orig[stub_size] = { 0 };
    SIZE_T out_bytes = 0;
    if (!ReadProcessMemory(hProcess, (LPVOID)stub_ptr, stub_buffer_orig, stub_size, &out_bytes) || out_bytes != stub_size) {
        return false;
    }

    const BYTE NOP = 0x90;
    if (stub_buffer_orig[0] != NOP) {
        return false;
    }
    // prepare the patched stub:
    const size_t syscall_pattern_full = 5;
    const BYTE syscall_fill_pattern[] = {
        0xB8, 0xFF, 0x00, 0x00, 0x00
    };
    if (stub_buffer_orig[1] != syscall_fill_pattern[0]) { // mov eax,[syscall ID]
        return false;
    }

    // prepare the patch to be applied on ZwQueryVirtualMemory:
    BYTE stub_buffer_patched[stub_size] = { 0 };
    ::memcpy(stub_buffer_patched, stub_buffer_orig, stub_size);

    DWORD delta = calcJmpAddr((DWORD)patch_space, (DWORD)_ZwQueryVirtualMemory);
    const BYTE jump_to_shc[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

    ::memcpy(stub_buffer_patched, jump_to_shc, sizeof(jump_to_shc));
    ::memcpy(stub_buffer_patched + 1, &delta, sizeof(delta));
    // prepare the trampoline:

    ULONG_PTR _ZwQueryVirtualMemory_continue = (ULONG_PTR)_ZwQueryVirtualMemory + syscall_pattern_full;

    BYTE func_patch[] = {
        0x3E, 0x83, 0x7C, 0x24, 0x0C, 0x0E, //cmp dword ptr ds:[esp+0x0C], 0x0E-> is MEMORY_INFORMATION_CLASS == MemoryImageExtensionInformation?
        0x75, 0x11, // jne [continue to function]
        0x3E, 0x81, 0x7C, 0x24, 0x10, 0x0D, 0xF0, 0x00, 0x0F,// cmp dword ptr ds:[esp+0x10], 0xF00F00D -> is ImageBase == module_ptr ?
        0x75, 0x06,// jne [continue to function]
        0xB8, 0xBB, 0x00, 0x00, 0xC0,// mov eax,C00000BB -> STATUS_NOT_SUPPORTED
        0xC3 //ret
    };
    size_t base_offset = 0xD;
    ::memcpy(func_patch + base_offset, &module_ptr, sizeof(DWORD));

    BYTE stub_buffer_trampoline[stub_size + sizeof(func_patch)] = { 0 };
    ::memcpy(stub_buffer_trampoline, func_patch, sizeof(func_patch));

    const size_t syscall_size = sizeof(syscall_fill_pattern);
    DWORD curr_va = (DWORD)patch_space + sizeof(func_patch) + syscall_size;
    DWORD delta2 = calcJmpAddr((DWORD)_ZwQueryVirtualMemory_continue, (DWORD)curr_va);

    // copy the syscall wrapper beginning:
    ::memcpy(stub_buffer_trampoline + sizeof(func_patch), stub_buffer_orig + pos, sizeof(syscall_fill_pattern));

    ::memcpy(stub_buffer_trampoline + sizeof(func_patch) + sizeof(syscall_fill_pattern), jump_to_shc, sizeof(jump_to_shc));
    ::memcpy(stub_buffer_trampoline + sizeof(func_patch) + sizeof(syscall_fill_pattern) + 1, &delta2, sizeof(delta2));

    const SIZE_T trampoline_full_size = sizeof(stub_buffer_trampoline);


    if (!WriteProcessMemory(hProcess, (LPVOID)_ZwQueryVirtualMemory, stub_buffer_patched, syscall_size, &out_bytes) || out_bytes != syscall_size) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, oldProtect, &oldProtect)) {
        return false;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)patch_space, stub_buffer_trampoline, trampoline_full_size, &out_bytes) || out_bytes != trampoline_full_size) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)patch_space, stub_size, PAGE_EXECUTE_READ, &oldProtect)) {
        return false;
    }
    FlushInstructionCache(hProcess, (LPVOID)stub_ptr, stub_size);
    return true;
#else
    return false;
#endif
}

bool apply_ntdll_patch64(HANDLE hProcess, LPVOID module_ptr)
{
#ifdef _WIN64
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) return false; // should never happen

    const SIZE_T pos = 8;
    const SIZE_T stub_size = 0x20;

    ULONG_PTR _ZwQueryVirtualMemory = (ULONG_PTR)GetProcAddress(hNtdll, "ZwQueryVirtualMemory");
    if (!_ZwQueryVirtualMemory || _ZwQueryVirtualMemory < pos) {
        return false;
    }
    ULONG_PTR stub_ptr = (ULONG_PTR)_ZwQueryVirtualMemory - pos;
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    LPVOID patch_space = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!patch_space) {
        return false;
    }

    BYTE stub_buffer_orig[stub_size] = { 0 };
    SIZE_T out_bytes = 0;
    if (!ReadProcessMemory(hProcess, (LPVOID)stub_ptr, stub_buffer_orig, stub_size, &out_bytes) || out_bytes != stub_size) {
        return false;
    }
    const BYTE nop_pattern[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (::memcmp(stub_buffer_orig, nop_pattern, sizeof(nop_pattern)) != 0) {
        return false;
    }

    // prepare the patched stub:
    const size_t syscall_pattern_full = 8;
    const size_t syscall_pattern_start = 4;
    const BYTE syscall_fill_pattern[] = {
        0x4C, 0x8B, 0xD1, //mov r10,rcx
        0xB8, 0xFF, 0x00, 0x00, 0x00 // mov eax,[syscall ID]
    };
    if (::memcmp(stub_buffer_orig + pos, syscall_fill_pattern, syscall_pattern_start) != 0) {
        return false;
    }

    // prepare the patch to be applied on ZwQueryVirtualMemory:

    BYTE stub_buffer_patched[stub_size] = { 0 };
    ::memcpy(stub_buffer_patched, stub_buffer_orig, stub_size);

    const BYTE jump_back[] = { 0xFF, 0x25, 0xF2, 0xFF, 0xFF, 0xFF };

    ::memcpy(stub_buffer_patched, &patch_space, sizeof(LPVOID));
    ::memset(stub_buffer_patched + pos, 0x90, syscall_pattern_full);
    ::memcpy(stub_buffer_patched + pos, jump_back, sizeof(jump_back));

    // prepare the trampoline:

    const BYTE jump_to_contnue[] = { 0xFF, 0x25, 0xEA, 0xFF, 0xFF, 0xFF };
    ULONG_PTR _ZwQueryVirtualMemory_continue = (ULONG_PTR)_ZwQueryVirtualMemory + syscall_pattern_full;

    BYTE func_patch[] = {
        0x49, 0x83, 0xF8, 0x0E, //cmp r8,0xE -> is MEMORY_INFORMATION_CLASS == MemoryImageExtensionInformation?
        0x75, 0x22, // jne [continue to function]
        0x48, 0x3B, 0x15, 0x0B, 0x00, 0x00, 0x00, // cmp rdx,qword ptr ds:[addr] -> is ImageBase == module_ptr ?
        0x75, 0x19, // jne [continue to function]
        0xB8, 0xBB, 0x00, 0x00, 0xC0, // mov eax,C00000BB -> STATUS_NOT_SUPPORTED
        0xC3 //ret
    };

    BYTE stub_buffer_trampoline[stub_size * 2] = { 0 };
    ::memcpy(stub_buffer_trampoline, func_patch, sizeof(func_patch));

    ::memcpy(stub_buffer_trampoline + stub_size, stub_buffer_orig, stub_size);
    ::memcpy(stub_buffer_trampoline + stub_size - sizeof(LPVOID), &module_ptr, sizeof(LPVOID));
    ::memcpy(stub_buffer_trampoline + stub_size, &_ZwQueryVirtualMemory_continue, sizeof(LPVOID));
    ::memcpy(stub_buffer_trampoline + stub_size + pos + syscall_pattern_full, jump_to_contnue, sizeof(jump_to_contnue));

    const SIZE_T trampoline_full_size = stub_size + pos + syscall_pattern_full + sizeof(jump_to_contnue);

    if (!WriteProcessMemory(hProcess, (LPVOID)stub_ptr, stub_buffer_patched, stub_size, &out_bytes) || out_bytes != stub_size) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, oldProtect, &oldProtect)) {
        return false;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)patch_space, stub_buffer_trampoline, trampoline_full_size, &out_bytes) || out_bytes != trampoline_full_size) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)patch_space, stub_size, PAGE_EXECUTE_READ, &oldProtect)) {
        return false;
    }
    FlushInstructionCache(hProcess, (LPVOID)stub_ptr, stub_size);
    return true;
#else
    return false;
#endif
}

bool apply_ntdll_patch(HANDLE hProcess, LPVOID module_ptr)
{
#ifdef _WIN64
    return apply_ntdll_patch64(hProcess, module_ptr);
#else
    return apply_ntdll_patch32(hProcess, module_ptr);
#endif
}
