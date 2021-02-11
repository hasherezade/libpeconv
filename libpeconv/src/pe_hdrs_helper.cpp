#include "peconv/pe_hdrs_helper.h"
#include "peconv/util.h"

using namespace peconv;

#ifdef _DEBUG
#include <iostream>
#endif

BYTE* peconv::get_nt_hdrs(IN const BYTE *pe_buffer, IN OPTIONAL size_t buffer_size)
{
    if (!pe_buffer) return nullptr;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (buffer_size != 0) {
        if (!peconv::validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)idh, sizeof(IMAGE_DOS_HEADER))) {
            return nullptr;
        }
    }
    if (peconv::is_bad_read_ptr(idh, sizeof(IMAGE_DOS_HEADER))) {
        return nullptr;
    }
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > kMaxOffset) return nullptr;

    IMAGE_NT_HEADERS32 *inh = (IMAGE_NT_HEADERS32 *)(pe_buffer + pe_offset);
    if (buffer_size != 0) {
        if (!peconv::validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)inh, sizeof(IMAGE_NT_HEADERS32))) {
            return nullptr;
        }
    }
    if (peconv::is_bad_read_ptr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return nullptr;
    }
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    return (BYTE*)inh;
}

IMAGE_NT_HEADERS32* peconv::get_nt_hdrs32(IN const BYTE *payload)
{
    if (!payload) return nullptr;

    BYTE *ptr = get_nt_hdrs(payload);
    if (!ptr) return nullptr;

    if (!is64bit(payload)) {
        return (IMAGE_NT_HEADERS32*)ptr;
    }
    return nullptr;
}

IMAGE_NT_HEADERS64* peconv::get_nt_hdrs64(IN const BYTE *payload)
{
    if (payload == nullptr) return nullptr;

    BYTE *ptr = get_nt_hdrs(payload);
    if (!ptr) return nullptr;

    if (is64bit(payload)) {
        return (IMAGE_NT_HEADERS64*)ptr;
    }
    return nullptr;
}

DWORD peconv::get_image_size(IN const BYTE *payload)
{
    if (!get_nt_hdrs(payload)) {
        return 0;
    }
    DWORD image_size = 0;
    if (is64bit(payload)) {
        IMAGE_NT_HEADERS64* nt64 = get_nt_hdrs64(payload);
        image_size = nt64->OptionalHeader.SizeOfImage;
    } else {
        IMAGE_NT_HEADERS32* nt32 = get_nt_hdrs32(payload);
        image_size = nt32->OptionalHeader.SizeOfImage;
    }
    return image_size;
}

bool peconv::update_image_size(IN OUT BYTE* payload, IN DWORD image_size)
{
    if (!get_nt_hdrs(payload)) {
        return false;
    }
    if (is64bit(payload)) {
        IMAGE_NT_HEADERS64* nt64 = get_nt_hdrs64(payload);
        nt64->OptionalHeader.SizeOfImage = image_size;
    }
    else {
        IMAGE_NT_HEADERS32* nt32 = get_nt_hdrs32(payload);
        nt32->OptionalHeader.SizeOfImage = image_size;
    }
    return true;
}

WORD peconv::get_nt_hdr_architecture(IN const BYTE *pe_buffer)
{
    void *ptr = get_nt_hdrs(pe_buffer);
    if (!ptr) return 0;

    IMAGE_NT_HEADERS32 *inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    if (peconv::is_bad_read_ptr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return 0;
    }
    return inh->OptionalHeader.Magic;
}

bool peconv::is64bit(IN const BYTE *pe_buffer)
{
    WORD arch = get_nt_hdr_architecture(pe_buffer);
    if (arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return true;
    }
    return false;
}

IMAGE_DATA_DIRECTORY* peconv::get_directory_entry(IN const BYTE *pe_buffer, IN DWORD dir_id, IN bool allow_empty)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return nullptr;

    BYTE* nt_headers = get_nt_hdrs((BYTE*)pe_buffer);
    if (!nt_headers) return nullptr;

    IMAGE_DATA_DIRECTORY* peDir = nullptr;
    if (is64bit(pe_buffer)) {
        IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    else {
        IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    if (!allow_empty && peDir->VirtualAddress == NULL) {
        return nullptr;
    }
    return peDir;
}

ULONGLONG peconv::get_image_base(IN const BYTE *pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer);
    if (!payload_nt_hdr) {
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

DWORD peconv::get_entry_point_rva(IN const BYTE *pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer);
    if (!payload_nt_hdr) {
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

bool peconv::update_entry_point_rva(IN OUT BYTE *pe_buffer, IN DWORD value)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer);
    if (!payload_nt_hdr) {
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

DWORD peconv::get_hdrs_size(IN const BYTE *pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer);
    if (!payload_nt_hdr) {
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

bool peconv::update_image_base(IN OUT BYTE* payload, IN ULONGLONG destImageBase)
{
    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (!payload_nt_hdr) {
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
inline const IMAGE_FILE_HEADER* fetch_file_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN const IMAGE_NT_HEADERS_T *payload_nt_hdr)
{
    if (!payload || !payload_nt_hdr) return nullptr;

    const IMAGE_FILE_HEADER *fileHdr = &(payload_nt_hdr->FileHeader);

    if (!validate_ptr((const LPVOID)payload, buffer_size, (const LPVOID)fileHdr, sizeof(IMAGE_FILE_HEADER))) {
        return nullptr;
    }
    return fileHdr;
}

const IMAGE_FILE_HEADER* peconv::get_file_hdr(IN const BYTE* payload, IN const size_t buffer_size)
{
    if (!payload) return nullptr;

    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (!payload_nt_hdr) {
        return nullptr;
    }
    if (is64bit(payload)) {
        return fetch_file_hdr(payload, buffer_size, (IMAGE_NT_HEADERS64*)payload_nt_hdr);
    }
    return fetch_file_hdr(payload, buffer_size, (IMAGE_NT_HEADERS32*)payload_nt_hdr);
}

template <typename IMAGE_NT_HEADERS_T>
inline const LPVOID fetch_opt_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN const IMAGE_NT_HEADERS_T *payload_nt_hdr)
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

LPVOID peconv::get_optional_hdr(IN const BYTE* payload, IN const size_t buffer_size)
{
    if (!payload) return nullptr;

    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
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
inline LPVOID fetch_section_hdrs_ptr(IN const BYTE* payload, IN const size_t buffer_size, IN const IMAGE_NT_HEADERS_T *payload_nt_hdr)
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

size_t peconv::get_sections_count(IN const BYTE* payload, IN const size_t buffer_size)
{
    const IMAGE_FILE_HEADER* fileHdr = get_file_hdr(payload, buffer_size);
    if (!fileHdr) {
        return 0;
    }
    return fileHdr->NumberOfSections;
}

bool peconv::is_valid_sections_hdr_offset(IN const BYTE* buffer, IN const size_t buffer_size)
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

PIMAGE_SECTION_HEADER peconv::get_section_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN size_t section_num)
{
    if (!payload) return nullptr;

    const size_t sections_count = peconv::get_sections_count(payload, buffer_size);
    if (section_num >= sections_count) {
        return nullptr;
    }

    LPVOID nt_hdrs = peconv::get_nt_hdrs(payload);
    if (!nt_hdrs) return nullptr; //this should never happened, because the get_sections_count did not fail

    LPVOID secptr = nullptr;
    //get the beginning of sections headers:
    if (is64bit(payload)) {
        secptr = fetch_section_hdrs_ptr<IMAGE_NT_HEADERS64>(payload, buffer_size, (IMAGE_NT_HEADERS64*)nt_hdrs);
    }
    else {
        secptr = fetch_section_hdrs_ptr<IMAGE_NT_HEADERS32>(payload, buffer_size, (IMAGE_NT_HEADERS32*)nt_hdrs);
    }
    //get the section header of given number:
    PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)(
        (ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * section_num)
    );
    //validate pointer:
    if (!validate_ptr((const LPVOID) payload, buffer_size, (const LPVOID) next_sec, sizeof(IMAGE_SECTION_HEADER))) {
        return nullptr;
    }
    return next_sec;
}

WORD peconv::get_file_characteristics(IN const BYTE* payload)
{
    if (!payload) return 0;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (!payload_nt_hdr) {
        return 0;
    }
    IMAGE_FILE_HEADER *fileHdr = nullptr;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
    }
    return fileHdr->Characteristics;
}

bool peconv::is_module_dll(IN const BYTE* payload)
{
    if (!payload) return false;
    WORD charact = get_file_characteristics(payload);
    return ((charact & IMAGE_FILE_DLL) != 0);
}

WORD peconv::get_dll_characteristics(IN const BYTE* payload)
{
    if (!payload) return 0;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (!payload_nt_hdr) {
        return 0;
    }
    WORD charact = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        charact = payload_nt_hdr64->OptionalHeader.DllCharacteristics;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        charact = payload_nt_hdr32->OptionalHeader.DllCharacteristics;
    }
    return charact;
}

bool peconv::set_subsystem(IN OUT BYTE* payload, IN WORD subsystem)
{
    if (!payload) return false;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (!payload_nt_hdr) {
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

WORD peconv::get_subsystem(IN const BYTE* payload)
{
    if (!payload) return 0;

    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        return payload_nt_hdr64->OptionalHeader.Subsystem;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        return payload_nt_hdr32->OptionalHeader.Subsystem;
    }
}

bool peconv::has_relocations(IN const BYTE *pe_buffer)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!relocDir) {
        return false;
    }
    return true;
}

IMAGE_EXPORT_DIRECTORY* peconv::get_export_directory(IN HMODULE modulePtr)
{
    return get_type_directory<IMAGE_EXPORT_DIRECTORY>(modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
}


IMAGE_COR20_HEADER * peconv::get_dotnet_hdr(IN const BYTE* module, IN size_t const module_size, IN const IMAGE_DATA_DIRECTORY * dotNetDir)
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

template <typename IMAGE_NT_HEADERS_T>
DWORD* _get_sec_alignment_ptr(const BYTE* modulePtr, bool is_raw)
{
    IMAGE_NT_HEADERS_T* hdrs = reinterpret_cast<IMAGE_NT_HEADERS_T*>(peconv::get_nt_hdrs(modulePtr));
    if (!hdrs) return nullptr;
    if (is_raw) {
        return &hdrs->OptionalHeader.FileAlignment;
    }
    return &hdrs->OptionalHeader.SectionAlignment;
}

DWORD peconv::get_sec_alignment(IN const BYTE* modulePtr, IN bool is_raw)
{
    DWORD* alignment = 0;
    if (peconv::is64bit(modulePtr)) {
        alignment = _get_sec_alignment_ptr<IMAGE_NT_HEADERS64>(modulePtr, is_raw);
    } else {
        alignment = _get_sec_alignment_ptr<IMAGE_NT_HEADERS32>(modulePtr, is_raw);
    }
    if (!alignment) return 0;
    return *alignment;
}

bool peconv::set_sec_alignment(IN OUT BYTE* modulePtr, IN bool is_raw, IN DWORD new_alignment)
{
    DWORD* alignment = 0;
    if (peconv::is64bit(modulePtr)) {
        alignment = _get_sec_alignment_ptr<IMAGE_NT_HEADERS64>(modulePtr, is_raw);
    }
    else {
        alignment = _get_sec_alignment_ptr<IMAGE_NT_HEADERS32>(modulePtr, is_raw);
    }
    if (!alignment) return false;

    *alignment = new_alignment;
    return true;
}

DWORD peconv::get_virtual_sec_size(IN const BYTE* pe_hdr, IN const PIMAGE_SECTION_HEADER sec_hdr, IN bool rounded)
{
    if (!pe_hdr || !sec_hdr) {
        return 0;
    }
    if (!rounded) {
        return sec_hdr->Misc.VirtualSize;;
    }
    //TODO: calculate real size, round up to Virtual Alignment
    DWORD alignment = peconv::get_sec_alignment((const PBYTE)pe_hdr, false);
    DWORD vsize = sec_hdr->Misc.VirtualSize;

    DWORD units = vsize / alignment;
    if ((vsize % alignment) > 0) units++;

    vsize = units * alignment;

    DWORD image_size = peconv::get_image_size(pe_hdr);
    //if it is bigger than the image size, use the size from the headers
    if ((sec_hdr->VirtualAddress + vsize) > image_size) {
        vsize = sec_hdr->Misc.VirtualSize;
    }
    return vsize;
}

PIMAGE_SECTION_HEADER peconv::get_last_section(IN const PBYTE pe_buffer, IN size_t pe_size, IN bool is_raw)
{
    SIZE_T module_end = peconv::get_hdrs_size(pe_buffer);
    const size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    if (sections_count == 0) {
        return nullptr;
    }
    PIMAGE_SECTION_HEADER last_sec = nullptr;
    //walk through sections
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(pe_buffer, pe_size, i);
        if (!sec) break;

        size_t new_end = is_raw ? (sec->PointerToRawData + sec->SizeOfRawData) : (sec->VirtualAddress + sec->Misc.VirtualSize);
        if (new_end > module_end) {
            module_end = new_end;
            last_sec = sec;
        }
    }
    return last_sec;
}

DWORD peconv::calc_pe_size(IN const PBYTE pe_buffer, IN size_t pe_size, IN bool is_raw)
{
    DWORD module_end = peconv::get_hdrs_size(pe_buffer);
    const size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    if (sections_count == 0) {
        return module_end;
    }
    //walk through sections
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(pe_buffer, pe_size, i);
        if (!sec) break;

        DWORD new_end = is_raw ? (sec->PointerToRawData + sec->SizeOfRawData) : (sec->VirtualAddress + sec->Misc.VirtualSize);
        if (new_end > module_end) module_end = new_end;
    }
    return module_end;
}

bool peconv::is_valid_sectons_alignment(IN const BYTE* payload, IN const SIZE_T payload_size, IN bool is_raw)
{
    if (payload == NULL) return false;

    const DWORD my_align = peconv::get_sec_alignment(payload, is_raw);
    if (my_align == 0) {
#ifdef _DEBUG
        std::cout << "Section alignment cannot be 0\n";
#endif
        return false;
    }
    const size_t sections_count = peconv::get_sections_count(payload, payload_size);
    if (sections_count == 0) {
        //no sections
        return false;
    }
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER next_sec = peconv::get_section_hdr(payload, payload_size, i);
        if (!next_sec) return false; //the number of the sections in header is out of scope

        const DWORD next_sec_addr = is_raw ? (next_sec->PointerToRawData) : (next_sec->VirtualAddress);

        SIZE_T sec_size = is_raw ? next_sec->SizeOfRawData : next_sec->Misc.VirtualSize;
        if (sec_size == 0) continue;
        if (next_sec->Misc.VirtualSize == 0) {
            continue; // if the VirtualSize == 0 the section will not be mapped anyways
        }
        if (next_sec_addr == 0) {
            //if cannot be 0 if the size is not 0
            return false;
        }

        //check only if raw_align is non-zero
        if (my_align && next_sec_addr % my_align != 0) {
#ifdef _DEBUG
            std::cout << "Section is misaligned\n";
#endif
            return false; //misaligned
        }
    }
    return true;
}
