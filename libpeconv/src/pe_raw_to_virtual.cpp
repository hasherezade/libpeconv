#include "pe_raw_to_virtual.h"

#include "util.h"
#include "pe_hdrs_helper.h"

using namespace peconv;

// Map raw PE into virtual memory of local process:
bool sections_raw_to_virtual(const BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    IMAGE_FILE_HEADER *fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    if (!validate_ptr((const LPVOID) payload, destBufferSize, (const LPVOID) payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr((const LPVOID) payload, destBufferSize, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }
        LPVOID section_mapped = destAddress + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = (BYTE*)payload +  next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;
        raw_end = next_sec->SizeOfRawData + next_sec->PointerToRawData;
        
        if (next_sec->VirtualAddress + sec_size > destBufferSize) {
            printf("[!] Virtual section size is out ouf bounds: %lx\n", static_cast<long>(sec_size));
            sec_size = SIZE_T(destBufferSize - next_sec->VirtualAddress);
            printf("[!] Truncated to maximal size: %lx\n", static_cast<long>(sec_size));
        }
        if (next_sec->VirtualAddress >= destBufferSize && sec_size != 0) {
            printf("[-] VirtualAddress of section is out ouf bounds: %lx\n", static_cast<long>(next_sec->VirtualAddress));
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > destBufferSize) {
            printf("[-] Raw section size is out ouf bounds: %lx\n", static_cast<long>(sec_size));
            return false;
        }
        //printf("[+] %s to: %p\n", next_sec->Name, section_raw_ptr);
        memcpy(section_mapped, section_raw_ptr, sec_size);
    }
    return true;
}

BYTE* peconv::pe_raw_to_virtual(const BYTE* payload, size_t in_size, size_t &out_size, bool executable, ULONGLONG desired_base)
{
    //check payload:
    BYTE* nt_hdr = get_nt_hrds(payload);
    if (nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }
    ULONGLONG oldImageBase = 0;
    DWORD payloadImageSize = 0;
    ULONGLONG entryPoint = 0;

	bool is64 = is64bit(payload);
    if (is64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr = (IMAGE_NT_HEADERS64*)nt_hdr;
        oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
        entryPoint = payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr = (IMAGE_NT_HEADERS32*)nt_hdr;
        oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
        entryPoint = payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    }

    SIZE_T written = 0;
    DWORD protect = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    BYTE* localCopyAddress = alloc_pe_buffer(payloadImageSize, protect, desired_base);
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return NULL;
    }
    //printf("Allocated local memory: %p size: %x\n", localCopyAddress, payloadImageSize);
    if (!sections_raw_to_virtual(payload, payloadImageSize, (BYTE*)localCopyAddress)) {
        printf("Could not copy PE file\n");
        return NULL;
    }
    out_size = payloadImageSize;
    return localCopyAddress;
}
