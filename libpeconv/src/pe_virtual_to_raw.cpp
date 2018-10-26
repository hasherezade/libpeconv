#include "peconv/pe_virtual_to_raw.h"

#include "peconv/util.h"
#include "peconv/pe_hdrs_helper.h"
#include "peconv/relocate.h"

#include <iostream>

using namespace peconv;

bool sections_virtual_to_raw(BYTE* payload, SIZE_T payload_size, OUT BYTE* destAddress, OUT SIZE_T *raw_size_ptr)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
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
    if (!validate_ptr(payload, payload_size, payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
#ifdef _DEBUG
    std::cout << "Coping sections:" << std::endl;
#endif
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

        if (next_sec->VirtualAddress + sec_size > payload_size) {
            std::cerr << "[!] Virtual section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            sec_size = SIZE_T(payload_size - next_sec->VirtualAddress);
            std::cerr << "[!] Truncated to maximal size: " << std::hex <<  sec_size << std::endl;
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
        memcpy(section_raw_ptr, section_mapped, sec_size);
    }
    if (raw_end > payload_size) raw_end = payload_size;
    if (raw_size_ptr != NULL) {
        (*raw_size_ptr) = raw_end;
    }
    return true;
}

BYTE* peconv::pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size, bool rebuffer)
{
    BYTE* in_buf = payload;
    if (rebuffer) {
        in_buf = (BYTE*) alloc_pe_buffer(in_size, PAGE_READWRITE);
        if (in_buf == NULL) return NULL;
        memcpy(in_buf, payload, in_size);
    }

    BYTE* out_buf = (BYTE*) alloc_pe_buffer(in_size, PAGE_READWRITE);
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
    }
    out_size = raw_size;
    return out_buf;
}
