#include "peconv/pe_raw_to_virtual.h"

#include "peconv/util.h"
#include "peconv/pe_hdrs_helper.h"

#include "peconv/logger.h"

using namespace peconv;

// Map raw PE into virtual memory of local process:
bool sections_raw_to_virtual(IN const BYTE* payload, IN SIZE_T payloadSize, OUT BYTE* destBuffer, IN SIZE_T destBufferSize)
{
    if (!payload || !destBuffer) return false;

    BYTE* payload_nt_hdr = get_nt_hdrs(payload, payloadSize);
    if (!payload_nt_hdr) {
        LOG_ERROR("Invalid PE at 0x%llx.", (unsigned long long)payload);
        return false;
    }

    const bool is64b = is64bit(payload);

    IMAGE_FILE_HEADER *fileHdr = nullptr;
    DWORD hdrsSize = 0;
    void* secptr = nullptr;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (void*)((ULONG_PTR)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (void*)((ULONG_PTR)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    DWORD first_raw = 0;
    //copy all the sections, one by one:
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONG_PTR)secptr + ((ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr(static_cast<const void*>(payload), payloadSize, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) { // check if fits in the source size
            return false;
        }
        const BYTE* next_sec_dest = destBuffer + (reinterpret_cast<const BYTE*>(next_sec) - payload);
        if (!validate_ptr(static_cast<const void*>(destBuffer), destBufferSize, next_sec_dest, IMAGE_SIZEOF_SECTION_HEADER)) { // check if fits in the destination size
            return false;
        }
        if (next_sec->PointerToRawData == 0 || next_sec->SizeOfRawData == 0) {
            continue; //skipping empty
        }
        void* section_mapped = destBuffer + next_sec->VirtualAddress;
        void* section_raw_ptr = (BYTE*)payload +  next_sec->PointerToRawData;
        size_t sec_size = next_sec->SizeOfRawData;
        
        if ((next_sec->VirtualAddress + sec_size) > destBufferSize) {
            sec_size = (destBufferSize > next_sec->VirtualAddress) ? SIZE_T(destBufferSize - next_sec->VirtualAddress) : 0;
            LOG_WARNING("Section %u: virtual size exceeds buffer, truncating to 0x%zx (buffer: 0x%zx).", i, sec_size, destBufferSize);
        }
        if (next_sec->VirtualAddress >= destBufferSize && sec_size != 0) {
            LOG_ERROR("Section %u: VirtualAddress 0x%lx is out of bounds.", i, next_sec->VirtualAddress);
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > destBufferSize) {
            LOG_ERROR("Section %u: raw data exceeds buffer (size: 0x%zx).", i, sec_size);
            return false;
        }

        // validate source:
        if (!validate_ptr(static_cast<const void*>(payload), payloadSize, section_raw_ptr, sec_size)) {
            if (next_sec->PointerToRawData > payloadSize) {
                LOG_WARNING("Section %u: PointerToRawData out of bounds, skipping.", i);
                continue;
            }
            // trim section
            sec_size = payloadSize - (next_sec->PointerToRawData);
        }
        // validate destination:
        if (!peconv::validate_ptr(destBuffer, destBufferSize, section_mapped, sec_size)) {
            LOG_WARNING("Section %u: destination out of bounds, skipping.", i);
            continue;
        }
        memcpy(section_mapped, section_raw_ptr, sec_size);
        if (first_raw == 0 || (next_sec->PointerToRawData < first_raw)) {
            first_raw = next_sec->PointerToRawData;
        }
    }

    //copy payload's headers:
    if (hdrsSize == 0) {
        hdrsSize= first_raw;
        LOG_INFO("SizeOfHeaders not set, using first section raw offset as fallback: 0x%lx.", hdrsSize);
    }
    if (!validate_ptr((const LPVOID)payload, destBufferSize, (const LPVOID)payload, hdrsSize)) {
        return false;
    }
    memcpy(destBuffer, payload, hdrsSize);
    return true;
}

BYTE* peconv::pe_raw_to_virtual(
    IN const BYTE* payload,
    IN size_t in_size,
    OUT size_t &out_size,
    IN OPTIONAL bool executable,
    IN OPTIONAL ULONG_PTR desired_base
)
{
    //check payload:
    BYTE* nt_hdr = get_nt_hdrs(payload);
    if (!nt_hdr) {
        LOG_ERROR("Invalid PE at 0x%llx.", (unsigned long long)(ULONG_PTR)payload);
        return nullptr;
    }
    DWORD payloadImageSize = 0;

    const bool is64 = is64bit(payload);
    if (is64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr = (IMAGE_NT_HEADERS64*)nt_hdr;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr = (IMAGE_NT_HEADERS32*)nt_hdr;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
    }
    payloadImageSize = peconv::round_up_to_unit(payloadImageSize, (DWORD)PAGE_SIZE);

    DWORD protect = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    BYTE* localCopyAddress = alloc_pe_buffer(payloadImageSize, protect, reinterpret_cast<void*>(desired_base));
    if (!localCopyAddress) {
        LOG_ERROR("Could not allocate memory in the current process.");
        return nullptr;
    }
    LOG_DEBUG("Allocated local memory: %p size: %x", localCopyAddress, payloadImageSize);
    if (!sections_raw_to_virtual(payload, in_size, localCopyAddress, payloadImageSize)) {
        LOG_ERROR("Could not copy PE file into virtual buffer.");
        peconv::free_pe_buffer(localCopyAddress);
        return nullptr;
    }
    out_size = payloadImageSize;
    return localCopyAddress;
}
