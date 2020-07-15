#include "peconv/remote_pe_reader.h"

#include <iostream>

#include "peconv/util.h"
#include "peconv/fix_imports.h"

using namespace peconv;

bool peconv::fetch_region_info(HANDLE processHandle, BYTE* moduleBase, MEMORY_BASIC_INFORMATION &page_info)
{
    memset(&page_info, 0, sizeof(MEMORY_BASIC_INFORMATION));
    SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID)moduleBase, &page_info, sizeof(page_info));
    if (out != sizeof(page_info)) {
        return false;
    }
    return true;
}

size_t peconv::fetch_region_size(HANDLE processHandle, BYTE* moduleBase)
{
    MEMORY_BASIC_INFORMATION page_info = { 0 };
    if (!peconv::fetch_region_info(processHandle, moduleBase, page_info)) {
        return 0;
    }
    if (page_info.Type == 0) {
        return false; //invalid type, skip it
    }
    if ((BYTE*)page_info.BaseAddress > moduleBase) {
        return 0; //should never happen
    }
    size_t offset = moduleBase - (BYTE*)page_info.BaseAddress;
    size_t area_size = page_info.RegionSize - offset;
    return area_size;
}

ULONGLONG peconv::fetch_alloc_base(HANDLE processHandle, BYTE* moduleBase)
{
    MEMORY_BASIC_INFORMATION page_info = { 0 };
    if (!peconv::fetch_region_info(processHandle, moduleBase, page_info)) {
        return 0;
    }
    if (page_info.Type == 0) {
        return 0; //invalid type, skip it
    }
    return (ULONGLONG) page_info.AllocationBase;
}

size_t peconv::read_remote_memory(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size)
{
    if (!buffer) {
        return 0;
    }
    memset(buffer, 0, buffer_size);

    SIZE_T read_size = 0;
    DWORD last_error = ERROR_SUCCESS;

    for (SIZE_T to_read_size = buffer_size; to_read_size > 0; to_read_size -= step_size)
    {
        if (ReadProcessMemory(processHandle, start_addr, buffer, to_read_size, &read_size)) {
            break;
        }
        // is it not the first attempt?
        if (last_error != ERROR_SUCCESS) {
            if (read_size == 0 && (last_error != ERROR_PARTIAL_COPY)) {
                last_error = GetLastError();
                break; // no progress, break
            }
        }

        last_error = GetLastError();

        if ((to_read_size < step_size) || step_size == 0) {
            break;
        }
        //otherwise, decrease the to_read_size, and try again...
    }

#ifdef _DEBUG
    if (read_size == 0) {
        std::cerr << "[WARNING] Cannot read memory. Last Error : " << last_error << std::endl;
    }
    else if (read_size < buffer_size) {
        std::cerr << "[WARNING] Read size: " << std::hex << read_size
            << " is smaller than the requested size: " << std::hex << buffer_size
            << ". Last Error: " << last_error << std::endl;

    }
#endif
    return static_cast<size_t>(read_size);
}

size_t read_remote_region(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size)
{
    if (buffer == nullptr) {
        return 0;
    }
    size_t region_size = peconv::fetch_region_size(processHandle, start_addr);
    if (region_size == 0) return false;

    if (region_size >= buffer_size) {
        return peconv::read_remote_memory(processHandle, start_addr, buffer, buffer_size, step_size);
    }
    return peconv::read_remote_memory(processHandle, start_addr, buffer, region_size, step_size);
}

size_t peconv::read_remote_area(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size)
{
    if (!buffer || !start_addr) {
        return 0;
    }
    memset(buffer, 0, buffer_size);

    size_t read = 0;
    for (read = 0; read < buffer_size; ) {
        size_t read_chunk = read_remote_region(processHandle, start_addr + read, buffer + read, buffer_size - read, step_size);
        if (read_chunk == 0) {
            size_t region_size = peconv::fetch_region_size(processHandle, start_addr);
            if (region_size == 0) break;
            //skip the region that could not be read:
            read += region_size;
            continue;
        }
        read += read_chunk;
    }
    return read;
}

bool peconv::read_remote_pe_header(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size)
{
    if (buffer == nullptr) {
        return false;
    }
    SIZE_T read_size = read_remote_memory(processHandle, start_addr, buffer, buffer_size);
    if (read_size == 0) {
        return false;
    }
    BYTE *nt_ptr = get_nt_hdrs(buffer);
    if (nt_ptr == nullptr) {
        return false;
    }
    const size_t nt_offset = nt_ptr - buffer;
    const size_t nt_size = peconv::is64bit(buffer) ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    const size_t min_size = nt_offset + nt_size;

    if (read_size < min_size) {
        std::cerr << "[-] [" << std::dec << get_process_id(processHandle) 
            << " ][" << std::hex << (ULONGLONG) start_addr 
            << "] Read size: " << std::hex << read_size 
            << " is smaller that the minimal size:" << get_hdrs_size(buffer) 
            << std::endl;
        return false;
    }
    //reading succeeded and the header passed the checks:
    return true;
}

namespace peconv {
    inline size_t roundup_to_unit(size_t size, size_t unit)
    {
        if (unit == 0) {
            return size;
        }
        size_t parts = size / unit;
        if (size % unit) parts++;
        return parts * unit;
    }
};

peconv::UNALIGNED_BUF peconv::get_remote_pe_section(HANDLE processHandle, BYTE *start_addr, const size_t section_num, OUT size_t &section_size, bool roundup)
{
    BYTE header_buffer[MAX_HEADER_SIZE] = { 0 };

    if (!read_remote_pe_header(processHandle, start_addr, header_buffer, MAX_HEADER_SIZE)) {
        return NULL;
    }
    PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(header_buffer, MAX_HEADER_SIZE, section_num);
    if (section_hdr == NULL || section_hdr->Misc.VirtualSize == 0) {
        return NULL;
    }
    size_t buffer_size = section_hdr->Misc.VirtualSize;
    if (roundup) {
        DWORD va = peconv::get_sec_alignment(header_buffer, false);
        if (va == 0) va = PAGE_SIZE;
        buffer_size = roundup_to_unit(section_hdr->Misc.VirtualSize, va);
    }
    UNALIGNED_BUF module_code = peconv::alloc_unaligned(buffer_size);
    if (module_code == NULL) {
        return NULL;
    }
    size_t read_size = read_remote_memory(processHandle, start_addr + section_hdr->VirtualAddress, module_code, buffer_size);
    if (read_size == 0) {
        peconv::free_unaligned(module_code);
        return NULL;
    }
    section_size = buffer_size;
    return module_code;
}

size_t peconv::read_remote_pe(const HANDLE processHandle, BYTE *start_addr, const size_t mod_size, OUT BYTE* buffer, const size_t bufferSize)
{
    if (buffer == nullptr) {
        std::cerr << "[-] Invalid output buffer: NULL pointer" << std::endl;
        return 0;
    }
    if (bufferSize < mod_size || bufferSize < MAX_HEADER_SIZE ) {
        std::cerr << "[-] Invalid output buffer: too small size!" << std::endl;
        return 0;
    }
    // read PE section by section
    PBYTE hdr_buffer = buffer;
    //try to read headers:
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        std::cerr << "[-] Failed to read the module header" << std::endl;
        return 0;
    }
    if (!is_valid_sections_hdr_offset(hdr_buffer, MAX_HEADER_SIZE)) {
        std::cerr << "[-] Sections headers are invalid or atypically aligned" << std::endl;
        return 0;
    }
    size_t sections_count = get_sections_count(hdr_buffer, MAX_HEADER_SIZE);
#ifdef _DEBUG
    std::cout << "Sections: " << sections_count  << std::endl;
#endif
    size_t read_size = MAX_HEADER_SIZE;

    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER hdr = get_section_hdr(hdr_buffer, MAX_HEADER_SIZE, i);
        if (!hdr) {
            std::cerr << "[-] Failed to read the header of section: " << i  << std::endl;
            break;
        }
        const DWORD sec_va = hdr->VirtualAddress;
        const DWORD sec_vsize = get_virtual_sec_size(hdr_buffer, hdr, true);
        if (sec_va + sec_vsize > bufferSize) {
            std::cerr << "[-] No more space in the buffer!" << std::endl;
            break;
        }
        if (sec_vsize > 0 && !read_remote_memory(processHandle, start_addr + sec_va, buffer + sec_va, sec_vsize)) {
            std::cerr << "[-] Failed to read the module section " << i <<" : at: " << std::hex << ULONG_PTR(start_addr + sec_va) << std::endl;
        }
        // update the end of the read area:
        size_t new_end = sec_va + sec_vsize;
        if (new_end > read_size) read_size = new_end;
    }
#ifdef _DEBUG
    std::cout << "Total read size: " << read_size << std::endl;
#endif
    return read_size;
}

DWORD peconv::get_remote_image_size(IN const HANDLE processHandle, IN BYTE *start_addr)
{
    BYTE hdr_buffer[MAX_HEADER_SIZE] = { 0 };
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        return 0;
    }
    return peconv::get_image_size(hdr_buffer);
}

bool peconv::dump_remote_pe(IN const char *out_path, 
    IN const HANDLE processHandle, 
    IN BYTE* start_addr, 
    IN OUT t_pe_dump_mode &dump_mode, 
    IN OPTIONAL peconv::ExportsMapper* exportsMap)
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
        std::cerr << "[-] Failed allocating buffer. Error: " << GetLastError() << std::endl;
        return false;
    }
    //read the module that it mapped in the remote process:
    const size_t read_size = read_remote_pe(processHandle, start_addr, mod_size, buffer, mod_size);
    if (read_size == 0) {
        std::cerr << "[-] Failed reading module. Error: " << GetLastError() << std::endl;
        peconv::free_pe_buffer(buffer, mod_size);
        buffer = nullptr;
        return false;
    }

    const bool is_dumped = peconv::dump_pe(out_path,
        buffer, mod_size,
        reinterpret_cast<ULONGLONG>(start_addr),
        dump_mode, exportsMap);

    peconv::free_pe_buffer(buffer, mod_size);
    buffer = nullptr;
    return is_dumped;
}

