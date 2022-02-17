#include "peconv/exceptions_parser.h"

#include "peconv/pe_hdrs_helper.h"

#ifdef _WIN64
bool peconv::setup_exceptions(IN BYTE* modulePtr, IN size_t moduleSize)
{
    if (moduleSize == 0) {
        const DWORD img_size = peconv::get_image_size((BYTE*)modulePtr);
        if (!img_size) {
            return false; // invalid image
        }
        moduleSize = img_size;
    }
    IMAGE_DATA_DIRECTORY* my_dir = peconv::get_directory_entry((const BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (!my_dir || !my_dir->VirtualAddress || !my_dir->Size) {
        return false;
    }
    RUNTIME_FUNCTION* exceptions_list = (RUNTIME_FUNCTION*)(my_dir->VirtualAddress + (ULONG_PTR)modulePtr);
    if (!validate_ptr(modulePtr, moduleSize, exceptions_list, my_dir->Size)) {
        return false;
    }
    //validate exceptions table:
    const size_t except_max_count = my_dir->Size / sizeof(RUNTIME_FUNCTION);
#ifdef _DEBUG
    std::cout << "[+] Found exception table of: " << std::dec << except_max_count << " entries\n";
#endif
    size_t i = 0;
    for (i = 0; i < except_max_count; i++) {
        RUNTIME_FUNCTION next_func = exceptions_list[i];
        BYTE* start_ptr = next_func.BeginAddress + modulePtr;
        size_t func_size = next_func.EndAddress - next_func.BeginAddress;
        if (!validate_ptr(modulePtr, moduleSize, start_ptr, func_size)) {
            break;
        }
    }
#ifdef _DEBUG
    std::cout << "[+] Valid exception entries: " << std::dec << i << " entries\n";
#endif
    if (i == 0) {
#ifdef _DEBUG
        std::cerr << "[-] None of the exceptions was valid\n";
#endif
        // none of the exceptions was valid
        return false;
    }
    if (RtlAddFunctionTable(exceptions_list, i, (ULONG_PTR)modulePtr)) {
        return true;
    }
    return false;
}
#endif
