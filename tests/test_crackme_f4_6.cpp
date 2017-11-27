#include "test_crackme_f4_6.h"

#include "peconv.h"
#include "file_helper.h"

#include "peconv.h"
using namespace peconv;

#include <iostream>
#include <string>
#include <map>

DWORD (_fastcall *imported_func_1)(ULONGLONG a1) = NULL;

VOID
WINAPI
my_GetSystemTime(
	_Out_ LPSYSTEMTIME lpSystemTime
	)
{
	GetSystemTime(lpSystemTime);
	lpSystemTime->wMonth = lpSystemTime->wMilliseconds % 12;
}

void __cdecl my_srand(unsigned int seed)
{
	printf("intercepred srand()\n");
	return srand(seed);
}

int __cdecl my_rand()
{
	int rval = rand();
	printf("intercepred rand() = %d\n", rval);
	return rval;
}

//For now this is for manual tests only:
int tests::decode_crackme_f4_6()
{
#ifndef _WIN64
	printf("Compile the loader as 64bit!\n");
	system("pause");
	return 0;
#endif
	char default_path[] = "C:\\FlareOn2017\\payload.dll";
	char *path = default_path;

	size_t v_size = 0;
	peconv:hooking_func_resolver my_res;
	my_res.add_hook("GetSystemTime", (FARPROC) &my_GetSystemTime);
	BYTE* loaded_pe = peconv::load_pe_executable(path, v_size, (peconv::t_function_resolver*) &my_res);
	if (!loaded_pe) {
		return -1;
	}

	ULONGLONG modifying_func_offset = 0x5d30 + (ULONGLONG) loaded_pe;

	//hook local func:
	ULONGLONG srand_offset = 0x7900 + (ULONGLONG) loaded_pe;
	ULONGLONG rand_offset = 0x78D4 + (ULONGLONG) loaded_pe;

	redirect_to_local64((void*)srand_offset, ULONGLONG(&my_srand));
	redirect_to_local64((void*)rand_offset, ULONGLONG(&my_rand));

	imported_func_1 = (DWORD (_fastcall *)(ULONGLONG)) (modifying_func_offset); 
	printf("Calling the main func:\n");
	DWORD returned = imported_func_1((ULONGLONG)loaded_pe);
	printf("Returned: %x\n", returned);
	
	//dump it now:
	size_t out_size = 0;
    
	BYTE* unmapped_module = peconv::pe_virtual_to_raw(loaded_pe, 
                                              v_size, 
                                              (ULONGLONG) loaded_pe, 
                                              out_size
                                          );
	if (unmapped_module) {
		char out_path[] = "modified_pe.dll";
		if (dump_to_file(out_path, unmapped_module, out_size)) {
			printf("Module dumped to: %s\n", out_path);
		}
		peconv::free_pe_buffer(unmapped_module, v_size);
	}
	peconv::free_pe_buffer(loaded_pe, v_size);
	return 0;
}
