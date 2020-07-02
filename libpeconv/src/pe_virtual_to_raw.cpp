#include "peconv/pe_virtual_to_raw.h"

#include "peconv/util.h"
#include "peconv/pe_hdrs_helper.h"
#include "peconv/relocate.h"

#include <iostream>

using namespace peconv;

bool sections_virtual_to_raw(BYTE* payload, SIZE_T payload_size, OUT BYTE* destAddress, OUT SIZE_T *raw_size_ptr)
{
    if (!payload || !destAddress) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hdrs(payload);
    if (payload_nt_hdr == NULL) {
        std::cerr << "Invalid payload: " << std::hex << (ULONGLONG) payload << std::endl;
        return false;
    }

    IMAGE_FILE_HEADER *fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*) payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*) payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }

    //copy all the sections, one by one:
#ifdef _DEBUG
    std::cout << "Coping sections:" << std::endl;
#endif
    DWORD first_raw = 0;
    SIZE_T raw_end = hdrsSize;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr(payload, payload_size, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
           return false;
        }
        
        LPVOID section_mapped = (BYTE*) payload + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = destAddress + next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;

        size_t new_end = sec_size + next_sec->PointerToRawData;
        if (new_end > raw_end) raw_end = new_end;

        if ((next_sec->VirtualAddress + sec_size) > payload_size) {
            std::cerr << "[!] Virtual section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            sec_size = (payload_size > next_sec->VirtualAddress) ? SIZE_T(payload_size - next_sec->VirtualAddress) : 0;
            std::cerr << "[!] Truncated to maximal size: " << std::hex << sec_size << ", buffer size: " << payload_size << std::endl;
        }
        if (next_sec->VirtualAddress > payload_size && sec_size != 0) {
            std::cerr << "[-] VirtualAddress of section is out ouf bounds: " << std::hex << next_sec->VirtualAddress << std::endl;
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > payload_size) {
            std::cerr << "[-] Raw section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            return false;
        }
#ifdef _DEBUG
        std::cout << "[+] " << next_sec->Name  << " to: "  << std::hex <<  section_raw_ptr << std::endl;
#endif
        //validate source:
        if (!peconv::validate_ptr(payload, payload_size, section_mapped, sec_size)) {
            std::cerr << "[-] Section " << i << ":  out ouf bounds, skipping... " << std::endl;
            continue;
        }
        //validate destination:
        if (!peconv::validate_ptr(destAddress, payload_size, section_raw_ptr, sec_size)) {
            std::cerr << "[-] Section " << i << ":  out ouf bounds, skipping... " << std::endl;
            continue;
        }
        memcpy(section_raw_ptr, section_mapped, sec_size);
        if (first_raw == 0 || (next_sec->PointerToRawData < first_raw)) {
            first_raw = next_sec->PointerToRawData;
        }
    }
    if (raw_end > payload_size) raw_end = payload_size;
    if (raw_size_ptr != NULL) {
        (*raw_size_ptr) = raw_end;
    }

    //copy payload's headers:
    if (hdrsSize == 0) {
        hdrsSize = first_raw;
#ifdef _DEBUG
        std::cout << "hdrsSize not filled, using calculated size: " << std::hex << hdrsSize << "\n";
#endif
    }
    if (!validate_ptr(payload, payload_size, payload, hdrsSize)) {
        return false;
    }
    memcpy(destAddress, payload, hdrsSize);
    return true;
}

BYTE* peconv::pe_virtual_to_raw(
    IN BYTE* payload,
    IN size_t in_size,
    IN ULONGLONG loadBase,
    OUT size_t &out_size,
    IN OPTIONAL bool rebuffer
)
{
    BYTE* out_buf = (BYTE*)alloc_pe_buffer(in_size, PAGE_READWRITE);
    if (out_buf == NULL) return NULL; //could not allocate output buffer

    BYTE* in_buf = payload;
    if (rebuffer) {
        in_buf = (BYTE*) alloc_pe_buffer(in_size, PAGE_READWRITE);
        if (in_buf == NULL) {
            free_pe_buffer(out_buf, in_size);
            return NULL;
        }
        memcpy(in_buf, payload, in_size);
    }

    ULONGLONG oldBase = get_image_base(in_buf);
    bool isOk = true;
    // from the loadBase go back to the original base
    if (!relocate_module(in_buf, in_size, oldBase, loadBase)) {
        //Failed relocating the module! Changing image base instead...
        if (!update_image_base(in_buf, (ULONGLONG)loadBase)) {
            std::cerr << "[-] Failed relocating the module!" << std::endl;
            isOk = false;
        } else {
#ifdef _DEBUG
            std::cerr << "[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!" << std::endl;
#endif
        }
    }
    SIZE_T raw_size = 0;
    if (isOk) {
        if (!sections_virtual_to_raw(in_buf, in_size, out_buf, &raw_size)) {
            isOk = false;
        }
    }
    if (rebuffer && in_buf != NULL) {
        free_pe_buffer(in_buf, in_size);
        in_buf = NULL;
    }
    if (!isOk) {
        free_pe_buffer(out_buf, in_size);
        out_buf = NULL;
        raw_size = 0;
    }
    out_size = raw_size;
    return out_buf;
}

BYTE* peconv::pe_realign_raw_to_virtual(
    IN const BYTE* payload,
    IN size_t in_size,
    IN ULONGLONG loadBase,
    OUT size_t &out_size
)
{
    out_size = in_size;
    BYTE* out_buf = (BYTE*)alloc_pe_buffer(out_size, PAGE_READWRITE);
    if (!out_buf) {
        out_size = 0;
        return nullptr;
    }
    memcpy(out_buf, payload, in_size);

    ULONGLONG oldBase = get_image_base(out_buf);
    bool isOk = true;
    // from the loadBase go back to the original base
    if (!relocate_module(out_buf, out_size, oldBase, loadBase)) {
        //Failed relocating the module! Changing image base instead...
        if (!update_image_base(out_buf, (ULONGLONG)loadBase)) {
            std::cerr << "[-] Failed relocating the module!" << std::endl;
            isOk = false;
        } else {
#ifdef _DEBUG
            std::cerr << "[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!" << std::endl;
#endif
        }
    }
    //---
    //set raw alignment the same as virtual
    DWORD v_alignment = peconv::get_sec_alignment((const PBYTE)payload, false);
    if (!peconv::set_sec_alignment(out_buf, true, v_alignment)) {
        isOk = false;
    }
    //set Raw pointers and sizes of the sections same as Virtual
    size_t sections_count = peconv::get_sections_count(out_buf, out_size);
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(out_buf, out_size, i);
        if (!sec) break;

        sec->Misc.VirtualSize = peconv::get_virtual_sec_size(out_buf, sec, true);
        sec->SizeOfRawData = sec->Misc.VirtualSize;
        sec->PointerToRawData = sec->VirtualAddress;
    }
    //!---
    if (!isOk) {
        free_pe_buffer(out_buf);
        out_buf = nullptr;
        out_size = 0;
    }
    return out_buf;
}
