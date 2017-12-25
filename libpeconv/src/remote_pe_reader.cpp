#include "peconv/remote_pe_reader.h"

#include <iostream>

#include "peconv/util.h"

using namespace peconv;

bool peconv::read_remote_pe_header(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size)
{
    SIZE_T read_size = 0;
    const SIZE_T step_size = 0x100;
    SIZE_T to_read_size = buffer_size;

    memset(buffer, 0, buffer_size);
    while (to_read_size >= step_size) {
        BOOL is_ok = ReadProcessMemory(processHandle, start_addr, buffer, to_read_size, &read_size);
        if (!is_ok) {
            //try to read less
            to_read_size -= step_size;
            continue;
        }
        if (get_nt_hrds(buffer) == NULL) {
            std::cerr << "[-] Cannot get the module header!" << std::endl;
            return false;
        }
        if (read_size < get_hdrs_size(buffer)) {
            std::cerr << "[-] Read size: " << read_size << " is smaller that the headers size:" << get_hdrs_size(buffer) << std::endl;
            return false;
        }
        //reading succeeded and the header passed the checks:
        return true;
    }
    return false;
}

BYTE* peconv::get_remote_pe_section(HANDLE processHandle, BYTE *start_addr, const size_t section_num, OUT size_t &section_size)
{
    BYTE header_buffer[MAX_HEADER_SIZE] = { 0 };
    SIZE_T read_size = 0;

    if (!read_remote_pe_header(processHandle, start_addr, header_buffer, MAX_HEADER_SIZE)) {
        return NULL;
    }
    PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(header_buffer, MAX_HEADER_SIZE, section_num);
    if (section_hdr == NULL || section_hdr->SizeOfRawData == 0) {
        return NULL;
    }
    BYTE *module_code = (BYTE*) calloc(section_hdr->SizeOfRawData, sizeof(BYTE));
    if (module_code == NULL) {
        return NULL;
    }
    ReadProcessMemory(processHandle, start_addr + section_hdr->VirtualAddress, module_code, section_hdr->SizeOfRawData, &read_size);
    if (read_size != section_hdr->SizeOfRawData) {
        free(module_code);
        return NULL;
    }
    section_size = read_size;
    return module_code;
}

void peconv::free_remote_pe_section(BYTE *section_buffer)
{
    free(section_buffer);
}

size_t peconv::read_remote_pe(const HANDLE processHandle, BYTE *start_addr, const size_t mod_size, OUT PBYTE buffer, const size_t bufferSize)
{
    if (buffer == nullptr) {
        std::cerr << "[-] Invalid output buffer: NULL pointer" << std::endl;
        return 0;
    }
    if (bufferSize < mod_size || bufferSize < MAX_HEADER_SIZE ) {
        std::cerr << "[-] Invalid output buffer: too small size!" << std::endl;
        return 0;
    }
    
    PBYTE hdr_buffer = buffer;
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        std::cerr << "[-] Failed to read the module header" << std::endl;
        return 0;
    }

    size_t read_size = MAX_HEADER_SIZE;
    //if not possible to read full module at once, try to read it section by section:
    size_t sections_count = get_sections_count(hdr_buffer, MAX_HEADER_SIZE);
#ifdef _DEBUG
    std::cout << "Sections: " << sections_count  << std::endl;
#endif
    for (size_t i = 0; i < sections_count; i++) {
        SIZE_T read_sec_size = 0;
        PIMAGE_SECTION_HEADER hdr = get_section_hdr(hdr_buffer, MAX_HEADER_SIZE, i);
        if (!hdr) {
            std::cerr << "[-] Failed to read the header of section: " << i  << std::endl;
            break;
        }
        const DWORD sec_va = hdr->VirtualAddress;
        const DWORD sec_size = hdr->SizeOfRawData;
        if (sec_va + sec_size > bufferSize) {
            std::cerr << "[-] No more space in the buffer!" << std::endl;
            break;
        }
        if (!ReadProcessMemory(processHandle, start_addr + sec_va, buffer + sec_va, sec_size, &read_sec_size)) {
        std::cerr << "[-] Failed to read the module section:: " << i  << std::endl;
        }
        // update the end of the read area:
        size_t new_end = sec_va + read_sec_size;
        if (new_end > read_size) read_size = new_end;
    }
#ifdef _DEBUG
    std::cout << "Total read size: " << read_size << std::endl;
#endif
    return read_size;
}

DWORD peconv::get_remote_image_size(const HANDLE processHandle, BYTE *start_addr)
{
    BYTE hdr_buffer[MAX_HEADER_SIZE] = { 0 };
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        return 0;
    }
    return peconv::get_image_size(hdr_buffer);
}

bool peconv::dump_remote_pe(const char *out_path, const HANDLE processHandle, PBYTE start_addr, bool unmap)
{
    DWORD mod_size = get_remote_image_size(processHandle, start_addr);
#ifdef _DEBUG
    std::cout << "Module Size: " << mod_size  << std::endl;
#endif
    if (mod_size == 0) {
        return false;
    }
    
    BYTE* buffer = peconv::alloc_pe_buffer(mod_size, PAGE_READWRITE);
    if (buffer == nullptr) {
        std::cerr << "Failed allocating buffer. Error: " << GetLastError() << std::endl;
        return false;
    }
    size_t read_size = 0;

    if ((read_size = read_remote_pe(processHandle, start_addr, mod_size, buffer, mod_size)) == 0) {
        std::cerr << "[-] Failed reading module. Error: " << GetLastError() << std::endl;
        peconv::free_pe_buffer(buffer, mod_size);
        buffer = NULL;
        return false;
    }
    BYTE* dump_data = buffer;
    size_t dump_size = mod_size;

    size_t out_size = 0;
    BYTE* unmapped_module = NULL;
    if (unmap) {
        unmapped_module = pe_virtual_to_raw(buffer, mod_size, (ULONGLONG)start_addr, out_size);
        if (unmapped_module != NULL) {
            dump_data = unmapped_module;
            dump_size = out_size;
        }
    }
    bool is_dumped = dump_to_file(out_path, dump_data, dump_size);
    peconv::free_pe_buffer(buffer, mod_size);
    buffer = NULL;
    if (unmapped_module) {
        peconv::free_pe_buffer(unmapped_module, mod_size);
    }
    return is_dumped;
}
