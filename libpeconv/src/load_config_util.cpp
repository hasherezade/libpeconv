#include "peconv/load_config_util.h"
#include "peconv/pe_hdrs_helper.h"

BYTE* peconv::get_load_config_ptr(BYTE* buffer, size_t buf_size)
{
    if (!buffer || !buf_size) return nullptr;
    IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(buffer, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!dir) {
        return 0;
    }
    DWORD entry_rva = dir->VirtualAddress;
    DWORD entry_size = dir->Size;
    if (!peconv::validate_ptr(buffer, buf_size, buffer + entry_rva, entry_size)) {
        return 0;
    }
    IMAGE_LOAD_CONFIG_DIRECTORY32* ldc = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY32*>((ULONG_PTR)buffer + entry_rva);
    return reinterpret_cast<BYTE*>(ldc);
}

peconv::t_load_config_ver peconv::get_load_config_version(BYTE* buffer, size_t buf_size, BYTE* ld_config_ptr)
{
    if (!buffer || !buf_size || !ld_config_ptr) peconv::LOAD_CONFIG_NONE;
    bool is64b = peconv::is64bit(buffer);

    if (!peconv::validate_ptr(buffer, buf_size, ld_config_ptr, sizeof(peconv::IMAGE_LOAD_CONFIG_DIR32_W7))) {
        return peconv::LOAD_CONFIG_NONE;
    }

    peconv::IMAGE_LOAD_CONFIG_DIR32_W7* smallest = (peconv::IMAGE_LOAD_CONFIG_DIR32_W7*)ld_config_ptr;
    const size_t curr_size = smallest->Size;

    if (is64b) {
        switch (curr_size) {
        case sizeof(peconv::IMAGE_LOAD_CONFIG_DIR64_W7) :
            return peconv::LOAD_CONFIG_W7_VER;
        case sizeof(peconv::IMAGE_LOAD_CONFIG_DIR64_W8) :
            return peconv::LOAD_CONFIG_W8_VER;
        case sizeof(peconv::IMAGE_LOAD_CONFIG_DIR64_W10) :
            return peconv::LOAD_CONFIG_W10_VER;
        default:
            return LOAD_CONFIG_UNK_VER;
        }
    }
    else {
        switch (curr_size) {
        case sizeof(peconv::IMAGE_LOAD_CONFIG_DIR32_W7) :
            return peconv::LOAD_CONFIG_W7_VER;
        case sizeof(peconv::IMAGE_LOAD_CONFIG_DIR32_W8) :
            return peconv::LOAD_CONFIG_W8_VER;
        case sizeof(peconv::IMAGE_LOAD_CONFIG_DIR32_W10) :
            return peconv::LOAD_CONFIG_W10_VER;
        default:
            return LOAD_CONFIG_UNK_VER;
        }
    }
    return LOAD_CONFIG_UNK_VER;
}
