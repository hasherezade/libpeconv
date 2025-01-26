#include "patch_ntdll.h"
#include <peconv.h>
bool apply_ntdll_patch(HANDLE hProcess)
{
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
    const BYTE nop_pattern[sizeof(LPVOID)] = {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
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

    BYTE stub_buffer_patched[stub_size] = { 0 };
    ::memcpy(stub_buffer_patched, stub_buffer_orig, stub_size);

    const BYTE jump_back[] = { 0xFF, 0x25, 0xF2, 0xFF, 0xFF, 0xFF };
    ::memcpy(stub_buffer_patched, &patch_space, sizeof(LPVOID));
    ::memset(stub_buffer_patched + pos, 0x90, syscall_pattern_full);
    ::memcpy(stub_buffer_patched + pos, jump_back, sizeof(jump_back));

    if (!WriteProcessMemory(hProcess, (LPVOID)stub_ptr, stub_buffer_patched, stub_size, &out_bytes) || out_bytes != stub_size) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)stub_ptr, stub_size, oldProtect, &oldProtect)) {
        return false;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)patch_space, stub_buffer_orig, stub_size, &out_bytes) || out_bytes != stub_size) {
        return false;
    }
    if (!VirtualProtectEx(hProcess, (LPVOID)patch_space, stub_size, PAGE_EXECUTE_READ, &oldProtect)) {
        return false;
    }
	return true;
}
