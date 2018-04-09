#include "peconv/pe_hdrs_helper.h"

using namespace peconv;

BYTE* peconv::get_nt_hrds(const BYTE *pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (IsBadReadPtr(idh, sizeof(IMAGE_DOS_HEADER))) {
        return NULL;
    }
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS32 *inh = (IMAGE_NT_HEADERS32 *)(pe_buffer + pe_offset);
    if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return NULL;
    }
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return (BYTE*)inh;
}

IMAGE_NT_HEADERS32* peconv::get_nt_hrds32(const BYTE *payload)
{
    if (payload == NULL) return NULL;

    BYTE *ptr = get_nt_hrds(payload);
    if (ptr == NULL) return NULL;

    bool is64b = is64bit(payload);
    if (!is64b) {
        return (IMAGE_NT_HEADERS32*)ptr;
    }
    return NULL;
}

IMAGE_NT_HEADERS64* peconv::get_nt_hrds64(const BYTE *payload)
{
    if (payload == NULL) return NULL;

    BYTE *ptr = get_nt_hrds(payload);
    if (ptr == NULL) return NULL;

    bool is64b = is64bit(payload);
    if (is64b) {
        return (IMAGE_NT_HEADERS64*)ptr;
    }
    return NULL;
}

DWORD peconv::get_image_size(const BYTE *payload)
{
    if (get_nt_hrds(payload) == NULL) {
        return 0;
    }
    DWORD image_size = 0;
    if (is64bit(payload)) {
        IMAGE_NT_HEADERS64* nt64 = get_nt_hrds64(payload);
        image_size = nt64->OptionalHeader.SizeOfImage;
    } else {
        IMAGE_NT_HEADERS32* nt32 = get_nt_hrds32(payload);
        image_size = nt32->OptionalHeader.SizeOfImage;
    }
    return image_size;
}

WORD peconv::get_nt_hdr_architecture(const BYTE *pe_buffer)
{
    void *ptr = get_nt_hrds(pe_buffer);
    if (ptr == NULL) return 0;

    IMAGE_NT_HEADERS32 *inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return 0;
    }
    return inh->OptionalHeader.Magic;
}

bool peconv::is64bit(const BYTE *pe_buffer)
{
    WORD arch = get_nt_hdr_architecture(pe_buffer);
    if (arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return true;
    }
    return false;
}

IMAGE_DATA_DIRECTORY* peconv::get_directory_entry(const BYTE *pe_buffer, DWORD dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    BYTE* nt_headers = get_nt_hrds((BYTE*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;
    if (is64bit((BYTE*)pe_buffer)) {
        IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    else {
        IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

ULONGLONG peconv::get_image_base(const BYTE *pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    ULONGLONG img_base = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        img_base = payload_nt_hdr64->OptionalHeader.ImageBase;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        img_base = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.ImageBase);
    }
    return img_base;
}

DWORD peconv::get_entry_point_rva(const BYTE *pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    DWORD value = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        value = payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        value = payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint;
    }
    return value;
}

bool peconv::update_entry_point_rva(BYTE *pe_buffer, DWORD value)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint = value;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint = value;
    }
    return true;
}

DWORD peconv::get_hdrs_size(const BYTE *pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    DWORD hdrs_size = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        hdrs_size = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        hdrs_size = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
    }
    return hdrs_size;
}

bool peconv::update_image_base(BYTE* payload, ULONGLONG destImageBase)
{
    bool is64b = is64bit(payload);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.ImageBase = (ULONGLONG)destImageBase;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.ImageBase = (DWORD)destImageBase;
    }
    return true;
}

template <typename IMAGE_NT_HEADERS_T>
inline const IMAGE_FILE_HEADER* fetch_file_hdr(const BYTE* payload, const size_t buffer_size, const IMAGE_NT_HEADERS_T *payload_nt_hdr)
{
    if (!payload || !payload_nt_hdr) return nullptr;

    const IMAGE_FILE_HEADER *fileHdr = &(payload_nt_hdr->FileHeader);

    if (!validate_ptr((const LPVOID)payload, buffer_size, (const LPVOID)fileHdr, sizeof(IMAGE_FILE_HEADER))) {
        return nullptr;
    }
    return fileHdr;
}

const IMAGE_FILE_HEADER* peconv::get_file_hdr(const BYTE* payload, const size_t buffer_size)
{
    if (!payload) return nullptr;

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (!payload_nt_hdr) {
        return nullptr;
    }
    if (is64bit(payload)) {
        return fetch_file_hdr(payload, buffer_size, (IMAGE_NT_HEADERS64*)payload_nt_hdr);
    }
    return fetch_file_hdr(payload, buffer_size, (IMAGE_NT_HEADERS32*)payload_nt_hdr);
}

template <typename IMAGE_NT_HEADERS_T>
inline const LPVOID fetch_opt_hdr(const BYTE* payload, const size_t buffer_size, const IMAGE_NT_HEADERS_T *payload_nt_hdr)
{
    if (!payload) return nullptr;

    const IMAGE_FILE_HEADER *fileHdr = fetch_file_hdr<IMAGE_NT_HEADERS_T>(payload, buffer_size, payload_nt_hdr);
    if (!fileHdr) {
        return nullptr;
    }
    const LPVOID opt_hdr = (const LPVOID) &(payload_nt_hdr->OptionalHeader);
    const size_t opt_size = fileHdr->SizeOfOptionalHeader;
    if (!validate_ptr((const LPVOID)payload, buffer_size, opt_hdr, opt_size)) {
        return nullptr;
    }
    return opt_hdr;
}

LPVOID peconv::get_optional_hdr(const BYTE* payload, const size_t buffer_size)
{
    if (!payload) return nullptr;

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    const IMAGE_FILE_HEADER* fileHdr = get_file_hdr(payload, buffer_size);
    if (!payload_nt_hdr || !fileHdr) {
        return nullptr;
    }
    if (is64bit(payload)) {
        return fetch_opt_hdr<IMAGE_NT_HEADERS64>(payload,buffer_size, (IMAGE_NT_HEADERS64*)payload_nt_hdr);
    }
    return fetch_opt_hdr<IMAGE_NT_HEADERS32>(payload, buffer_size, (IMAGE_NT_HEADERS32*)payload_nt_hdr);
}

template <typename IMAGE_NT_HEADERS_T>
inline LPVOID fetch_section_hdrs_ptr(const BYTE* payload, const size_t buffer_size, const IMAGE_NT_HEADERS_T *payload_nt_hdr)
{
    const IMAGE_FILE_HEADER *fileHdr = fetch_file_hdr<IMAGE_NT_HEADERS_T>(payload, buffer_size, payload_nt_hdr);
    if (!fileHdr) {
        return nullptr;
    }
    const size_t opt_size = fileHdr->SizeOfOptionalHeader;
    BYTE* opt_hdr = (BYTE*)fetch_opt_hdr(payload, buffer_size, payload_nt_hdr);
    if (!validate_ptr((const LPVOID)payload, buffer_size, opt_hdr, opt_size)) {
        return nullptr;
    }
    //sections headers starts right after the end of the optional header
    return (LPVOID)(opt_hdr + opt_size);
}

size_t peconv::get_sections_count(const BYTE* payload, const size_t buffer_size)
{
    const IMAGE_FILE_HEADER* fileHdr = get_file_hdr(payload, buffer_size);
    if (!fileHdr) {
        return 0;
    }
    return fileHdr->NumberOfSections;
}

bool peconv::is_valid_sections_hdr(BYTE* buffer, const size_t buffer_size)
{
    size_t sec_count = peconv::get_sections_count(buffer, buffer_size);
    if (sec_count == 0) {
        //no sections found - a valid PE should have at least one section
        return false;
    }
    PIMAGE_SECTION_HEADER last_hdr = get_section_hdr(buffer, buffer_size, sec_count - 1);
    if (!last_hdr) {
        //could not fetch the last section
        return false;
    }
    return true;
}


PIMAGE_SECTION_HEADER peconv::get_section_hdr(const BYTE* payload, const size_t buffer_size, size_t section_num)
{
    if (!payload) return nullptr;

    const size_t sections_count = peconv::get_sections_count(payload, buffer_size);
    if (section_num >= sections_count) {
        return nullptr;
    }

    LPVOID nt_hdrs = peconv::get_nt_hrds(payload);
    LPVOID secptr = nullptr;
    
    if (is64bit(payload)) {
        secptr = fetch_section_hdrs_ptr<IMAGE_NT_HEADERS64>(payload, buffer_size, (IMAGE_NT_HEADERS64*)nt_hdrs);
    }
    else {
        secptr = fetch_section_hdrs_ptr<IMAGE_NT_HEADERS32>(payload, buffer_size, (IMAGE_NT_HEADERS32*)nt_hdrs);
    }

    PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)(
        (ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * section_num)
    );

    //validate pointer
    if (!validate_ptr((const LPVOID) payload, buffer_size, (const LPVOID) next_sec, sizeof(IMAGE_SECTION_HEADER))) {
        return NULL;
    }
    return next_sec;
}

bool peconv::is_module_dll(const BYTE* payload)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    IMAGE_FILE_HEADER *fileHdr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
    }
    DWORD flag = fileHdr->Characteristics & 0x2000;
    return (flag != 0);
}

bool peconv::set_subsystem(BYTE* payload, WORD subsystem)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.Subsystem = subsystem;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.Subsystem = subsystem;
    }
    return true;
}

WORD peconv::get_subsystem(const BYTE* payload)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        return payload_nt_hdr64->OptionalHeader.Subsystem;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        return payload_nt_hdr32->OptionalHeader.Subsystem;
    }
}

bool peconv::has_relocations(BYTE *pe_buffer)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
        return false;
    }
    return true;
}

template <typename IMAGE_TYPE_DIRECTORY>
IMAGE_TYPE_DIRECTORY* peconv::get_type_directory(HMODULE modulePtr, DWORD dir_id)
{
    IMAGE_DATA_DIRECTORY *my_dir = peconv::get_directory_entry((const BYTE*) modulePtr, dir_id);
    if (my_dir == NULL) return NULL;

    DWORD dir_addr = my_dir->VirtualAddress;
    if (dir_addr == 0) return NULL;

    return (IMAGE_TYPE_DIRECTORY*)(dir_addr + (ULONG_PTR) modulePtr);
}

IMAGE_EXPORT_DIRECTORY* peconv::get_export_directory(HMODULE modulePtr)
{
    return get_type_directory<IMAGE_EXPORT_DIRECTORY>(modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
}

IMAGE_COR20_HEADER* peconv::get_dotnet_hdr(PBYTE module, size_t module_size, IMAGE_DATA_DIRECTORY* dotNetDir)
{
    DWORD rva = dotNetDir->VirtualAddress;
    DWORD hdr_size = dotNetDir->Size;
    if (!peconv::validate_ptr(module, module_size, module + rva, hdr_size)) {
        return nullptr;
    }
    IMAGE_COR20_HEADER *dnet_hdr = (IMAGE_COR20_HEADER*)(module + rva);
    if (!peconv::validate_ptr(module, module_size, module + dnet_hdr->MetaData.VirtualAddress, dnet_hdr->MetaData.Size)) {
        return nullptr;
    }
    DWORD* signature_ptr = (DWORD*)(module + dnet_hdr->MetaData.VirtualAddress);
    const DWORD dotNetSign = 0x424A5342;
    if (*signature_ptr != dotNetSign) {
        //invalid header
        return nullptr;
    }
    return dnet_hdr;
}

