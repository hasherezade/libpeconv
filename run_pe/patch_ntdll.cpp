#include "patch_ntdll.h"
#include <peconv.h>

bool patch_hotpaching_func64(HANDLE hProcess)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) return false; // should never happen

    const SIZE_T stub_size = 0x20;
    const BYTE hotpatch_patch[] = {
        0xB8, 0xBB, 0x00, 0x00, 0xC0, // mov eax,C00000BB -> STATUS_NOT_SUPPORTED
        0xC3 //ret
    };

    // syscall stub template
    const size_t syscall_pattern_full = 8;
    const size_t syscall_pattern_start = 4;
    const BYTE syscall_fill_pattern[] = {
        0x4C, 0x8B, 0xD1, //mov r10,rcx
        0xB8, 0xFF, 0x00, 0x00, 0x00 // mov eax,[syscall ID]
    };

    ULONG_PTR _NtManageHotPatch = (ULONG_PTR)GetProcAddress(hNtdll, "NtManageHotPatch");
    if (!_NtManageHotPatch) {
        return false;
    }
    ULONG_PTR stub_ptr = (ULONG_PTR)_NtManageHotPatch;
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    BYTE stub_buffer_orig[stub_size] = { 0 };
    SIZE_T out_bytes = 0;
    if (!ReadProcessMemory(hProcess, (LPVOID)stub_ptr, stub_buffer_orig, stub_size, &out_bytes) || out_bytes != stub_size) {
        return false;
    }
    // confirm it is a valid syscall stub:
    if (::memcmp(stub_buffer_orig, syscall_fill_pattern, syscall_pattern_start) != 0) {
        return false;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)stub_ptr, hotpatch_patch, sizeof(hotpatch_patch), &out_bytes) || out_bytes != sizeof(hotpatch_patch)) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, oldProtect, &oldProtect)) {
        return false;
    }
    return true;
}

bool apply_ntdll_patch64(HANDLE hProcess, LPVOID module_ptr)
{
#ifndef _WIN64
    return false;
#else
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) return false; // should never happen

    ULONGLONG pos = 8;
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
    const BYTE nop_pattern[] = {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
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
    if (!patch_hotpaching_func64(hProcess)) {
        return false;
    }
    return true;
#endif
}
