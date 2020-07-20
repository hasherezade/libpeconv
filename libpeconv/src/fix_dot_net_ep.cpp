#include "fix_dot_net_ep.h"
#include <peconv.h>

#include <string>
#include <map>

class ListImportNames : public peconv::ImportThunksCallback
{
public:
    ListImportNames(BYTE* _modulePtr, size_t _moduleSize, std::map<std::string, DWORD> &name_to_addr)
        : ImportThunksCallback(_modulePtr, _moduleSize), nameToAddr(name_to_addr)
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
        DWORD call_via_rva = static_cast<DWORD>((ULONG_PTR)call_via - (ULONG_PTR)this->modulePtr);
#ifdef _DEBUG
        std::cout << "via RVA: " << std::hex << call_via_rva << " : ";
#endif
        bool is_by_ord = (desc->u1.Ordinal & ordinal_flag) != 0;
        if (!is_by_ord) {
            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
            LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
#ifdef _DEBUG
            std::cout << "name: " << func_name << std::endl;
#endif
            nameToAddr[func_name] = call_via_rva;
        }
        return true;
    }

    std::map<std::string, DWORD> &nameToAddr;
};

DWORD find_corexemain(BYTE *buf, size_t buf_size)
{
    std::map<std::string, DWORD> name_to_addr;
    ListImportNames callback(buf, buf_size, name_to_addr);
    if (!peconv::process_import_table(buf, buf_size, &callback)) return 0;

    std::map<std::string, DWORD>::iterator found = name_to_addr.find("_CorExeMain");
    if (found != name_to_addr.end()) return found->second;

    found = name_to_addr.find("_CorDllMain");
    if (found != name_to_addr.end()) return found->second;

    return 0;
}

BYTE* search_jump(BYTE *buf, size_t buf_size, const DWORD cor_exe_main_thunk, const ULONGLONG img_base)
{
    // search the jump pattern, i.e.:
    //JMP DWORD NEAR [0X402000] : FF 25 00204000
    const size_t jmp_size = 2;
    const BYTE jmp_pattern[jmp_size] = { 0xFF, 0x25 };

    const size_t arg_size = sizeof(DWORD);
    if ((jmp_size + arg_size) > buf_size) {
        return nullptr;
    }
    const size_t end_offset = buf_size - (jmp_size + arg_size);

    for (size_t i = end_offset; // search backwards
        (i + 1) != 0; // this is unsigned comparison, so we cannot do: i >= 0
        i--) // go back by one BYTE
    {
        if (buf[i] == jmp_pattern[0] && buf[i + 1] == jmp_pattern[1]) { // JMP
            DWORD* addr = (DWORD*)(&buf[i + jmp_size]);
            DWORD rva = static_cast<DWORD>((*addr) - img_base);
            if (rva == cor_exe_main_thunk) {
#ifdef _DEBUG
                std::cout << "Found call to _CorExeMain\n";
#endif
                return buf + i;
            }
            else {
                std::cout << "[!] Mismatch: " << std::hex << rva << " vs _CorExeMain: " << cor_exe_main_thunk << std::endl;
            }
        }
    }
    return nullptr;
}

bool fix_dot_net_ep(BYTE *pe_buffer, size_t pe_buffer_size)
{
    if (!pe_buffer) return false;

    if (peconv::is64bit(pe_buffer)) {
        //64bit .NET files have EP=0
        peconv::update_entry_point_rva(pe_buffer, 0);
        return true;
    }

    DWORD ep_rva = peconv::get_entry_point_rva(pe_buffer);
    std::cout << "[*] This is a .NET payload and may require Enty Point corection. Current EP: " << std::hex << ep_rva << "\n";

    PIMAGE_SECTION_HEADER sec_hdr = peconv::get_section_hdr(pe_buffer, pe_buffer_size, 0);
    if (!sec_hdr) return false;

    BYTE *sec_ptr = pe_buffer + sec_hdr->VirtualAddress;
    if (!peconv::validate_ptr(pe_buffer, pe_buffer_size, sec_ptr, sec_hdr->SizeOfRawData)) {
        return false;
    }
    ULONGLONG img_base = peconv::get_image_base(pe_buffer);
    DWORD cor_exe_main_thunk = find_corexemain(pe_buffer, pe_buffer_size);
    if (!cor_exe_main_thunk) {
        return false;
    }
    BYTE* jump_ptr = search_jump(sec_ptr, sec_hdr->SizeOfRawData, cor_exe_main_thunk, img_base);
    if (jump_ptr == nullptr) return false;

    size_t offset = jump_ptr - pe_buffer;
    peconv::update_entry_point_rva(pe_buffer, static_cast<DWORD>(offset));
    std::cout << "[*] Found possible Entry Point: " << std::hex << offset << std::endl;
    return true;
}

bool is_dot_net(BYTE *pe_buffer, size_t pe_buffer_size)
{
    if (!pe_buffer) return false;

    IMAGE_DATA_DIRECTORY* dotnet_ptr = peconv::get_directory_entry(pe_buffer, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, false);
    if (!dotnet_ptr) return false;

    if (peconv::get_dotnet_hdr(pe_buffer, pe_buffer_size, dotnet_ptr)) {
        return true;
    }
    return false;
}
