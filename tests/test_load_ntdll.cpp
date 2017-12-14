#include "test_load_ntdll.h"

#include "peconv.h"
#include "file_helper.h"

#include <iostream>
#include "shellcodes.h"

int (_cdecl *ntdll_tolower) (int) = NULL;

NTSTATUS (NTAPI *ntdll_ZwAllocateVirtualMemory)(
  _In_    HANDLE    ProcessHandle,
  _Inout_ PVOID     *BaseAddress,
  _In_    ULONG_PTR ZeroBits,
  _Inout_ PSIZE_T   RegionSize,
  _In_    ULONG     AllocationType,
  _In_    ULONG     Protect
) = NULL;

//For now this is for manual tests only:
int tests::test_ntdll(char *path)
{
	CHAR ntdllPath[MAX_PATH];
    ExpandEnvironmentStrings("%SystemRoot%\\system32\\ntdll.dll", ntdllPath, MAX_PATH);

    size_t v_size = 0;
    BYTE *ntdll_module = peconv::load_pe_module(ntdllPath, v_size, true, true);
    if (!ntdll_module) {
        return -1;
    }
	bool is64 = peconv::is64bit(ntdll_module);
    std::cout << "NTDLL loaded" << is64 << std::endl;
    FARPROC n_offset = peconv::get_exported_func(ntdll_module, "tolower");
    if (n_offset == NULL) {
        return -1;
    }
    std::cout << "Got tolower: " << n_offset << std::endl;
    ntdll_tolower = (int (_cdecl *) (int)) n_offset;
    int out = ntdll_tolower('C');
    std::cout << "To lower char: " << (char) out << std::endl;

    n_offset = peconv::get_exported_func(ntdll_module, "ZwAllocateVirtualMemory");
    if (n_offset == NULL) {
        return -1;
    }
    PVOID base_addr = 0;
    SIZE_T buffer_size = 0x200;
    ntdll_ZwAllocateVirtualMemory = (NTSTATUS (NTAPI *)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG)) n_offset;
	NTSTATUS status = ntdll_ZwAllocateVirtualMemory(
		GetCurrentProcess(), &base_addr, 0, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
		);

	if (status != S_OK) {
		return -1;
	}
    printf("allocated: %p\n", base_addr);
#ifndef _WIN64
    memcpy(base_addr, messageBox32bit_sc, sizeof(messageBox32bit_sc));
#else
    memcpy(base_addr, messageBox64bit_sc, sizeof(messageBox64bit_sc));
#endif
	void (*shellc)(void) = (void (*)(void))base_addr;
    shellc();

    return 0;
}
