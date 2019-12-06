#include "test_imp_list.h"

using namespace peconv;

class ListImportThunks : public ImportThunksCallback
{
public:
    ListImportThunks(BYTE* _modulePtr, size_t _moduleSize)
        : ImportThunksCallback(_modulePtr, _moduleSize)
    {
    }

    virtual bool processThunks(LPSTR lib_name, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr)
    {
        if (this->is64b) {
            IMAGE_THUNK_DATA64* desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);
            ULONGLONG* call_via = reinterpret_cast<ULONGLONG*>(firstThunkPtr);
            return processThunks_tpl<ULONGLONG, IMAGE_THUNK_DATA64>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG64);
        }
        IMAGE_THUNK_DATA32* desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);
        DWORD* call_via = reinterpret_cast<DWORD*>(firstThunkPtr);
        return processThunks_tpl<DWORD, IMAGE_THUNK_DATA32>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG32);
    }

protected:
    template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
    bool processThunks_tpl(LPSTR lib_name, T_IMAGE_THUNK_DATA* desc, T_FIELD* call_via, T_FIELD ordinal_flag)
    {
        ULONG_PTR call_via_rva = (ULONG_PTR)call_via - (ULONG_PTR)this->modulePtr;
        std::cout << "via RVA: " << std::hex << call_via_rva << " : " << lib_name << " : ";

        bool is_by_ord = desc->u1.Ordinal & ordinal_flag;
        if (is_by_ord) {
            T_FIELD raw_ordinal = desc->u1.Ordinal & (~ordinal_flag);
            std::cout << "ord: " << raw_ordinal << std::endl;
        }
        else {
            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
            LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
            std::cout << "name: " << func_name << std::endl;
        }
        return true;
    }
};

bool list_imports(IN BYTE* modulePtr, IN size_t moduleSize)
{
    if (moduleSize == 0) {
        moduleSize = peconv::get_image_size((const BYTE*)modulePtr);
    }
    if (moduleSize == 0) return false;

    ListImportThunks callback(modulePtr, moduleSize);
    return peconv::process_import_table(modulePtr, moduleSize, &callback);
}

int tests::imp_list(char *my_path)
{
    size_t v_size = 0;
    std::cout << "Module: " << my_path << "\n";
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(my_path, v_size, true, true);
    if (!loaded_pe) {
        std::cout << "Loading failed!\n";
        return -1;
    }

    bool is_ok = list_imports(loaded_pe, v_size);

    peconv::free_pe_buffer(loaded_pe);
    return is_ok;
}
