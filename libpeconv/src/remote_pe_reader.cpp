#include "peconv/remote_pe_reader.h"

#include <iostream>

#include "peconv/util.h"
#include "peconv/fix_imports.h"

using namespace peconv;

bool peconv::fetch_region_info(HANDLE processHandle, LPVOID moduleBase, MEMORY_BASIC_INFORMATION &page_info)
{
    memset(&page_info, 0, sizeof(MEMORY_BASIC_INFORMATION));
    SIZE_T out = VirtualQueryEx(processHandle, moduleBase, &page_info, sizeof(page_info));
    if (out != sizeof(page_info)) {
        return false;
    }
    return true;
}

size_t _fetch_region_size(MEMORY_BASIC_INFORMATION &page_info, LPVOID moduleBase)
{
    if (page_info.Type == 0) {
        return false; //invalid type, skip it
    }
    if ((BYTE*)page_info.BaseAddress > moduleBase) {
        return 0; //should never happen
    }
    const size_t offset = (ULONG_PTR)moduleBase - (ULONG_PTR)page_info.BaseAddress;
    const size_t area_size = page_info.RegionSize - offset;
    return area_size;
}

size_t peconv::fetch_region_size(HANDLE processHandle, LPVOID moduleBase)
{
    MEMORY_BASIC_INFORMATION page_info = { 0 };
    if (!peconv::fetch_region_info(processHandle, moduleBase, page_info)) {
        return 0;
    }
    const size_t area_size = _fetch_region_size(page_info, moduleBase);
    return area_size;
}

ULONGLONG peconv::fetch_alloc_base(HANDLE processHandle, LPVOID moduleBase)
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

namespace peconv {
    /**
    Performs a binary search along with ReadProcessMemory, trying to find the biggest size of memory (within the buffer_size) that can be read. The search stops when the minimal_size was reached.
    The given minimal_size must be non-zero, and smaller than the buffer_size.
    If the size matching the constraints was found, it reads that many bytes to the buffer.
    */
    SIZE_T _search_readable_size(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T minimal_size)
    {
        if (!buffer || buffer_size == 0) {
            return 0;
        }
        if ((buffer_size < minimal_size) || minimal_size == 0) {
            return 0;
        }
        SIZE_T last_failed_size = buffer_size;
        SIZE_T last_success_size = 0;

        SIZE_T test_read_size = 0;
        if (!ReadProcessMemory(processHandle, start_addr, buffer, minimal_size, &test_read_size)) {
            //cannot read even the minimal size, quit trying
            return test_read_size;
        }
        last_success_size = minimal_size;

        SIZE_T read_size = 0;
        SIZE_T to_read_size = buffer_size/2;

        while (to_read_size > minimal_size && to_read_size < buffer_size)
        {
            read_size = 0;
            if (ReadProcessMemory(processHandle, start_addr, buffer, to_read_size, &read_size)) {
                last_success_size = to_read_size;
            }
            else {
                last_failed_size = to_read_size;
            }
            const size_t delta = (last_failed_size - last_success_size) / 2;
            if (delta == 0) break;
            to_read_size = last_success_size + delta;
        }
        if (last_success_size) {
            read_size = 0;
            memset(buffer, 0, buffer_size);
            ReadProcessMemory(processHandle, start_addr, buffer, last_success_size, &read_size);
            return read_size;
        }
        return 0;
    }
};

size_t peconv::read_remote_memory(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T minimal_size)
{
    if (!buffer || buffer_size == 0) {
        return 0;
    }
    memset(buffer, 0, buffer_size);

    SIZE_T read_size = 0;
    DWORD last_error = ERROR_SUCCESS;

    while (buffer_size > 0)
    {
        if (ReadProcessMemory(processHandle, start_addr, buffer, buffer_size, &read_size)) {
            break;
        }
        last_error = GetLastError();
        if (last_error != ERROR_SUCCESS) {
            if (read_size == 0 && (last_error != ERROR_PARTIAL_COPY)) {
                break; // break
            }
        }
        if (last_error == ERROR_PARTIAL_COPY) {
            read_size = peconv::_search_readable_size(processHandle, start_addr, buffer, buffer_size, minimal_size);
#ifdef _DEBUG
            std::cout << "peconv::search_readable_size res: " << std::hex << read_size << std::endl;
#endif
        }
        break;
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

size_t peconv::read_remote_region(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const bool force_access, const SIZE_T minimal_size)
{
    if (!buffer || buffer_size == 0) {
        return 0;
    }
    MEMORY_BASIC_INFORMATION page_info = { 0 };
    if (!peconv::fetch_region_info(processHandle, start_addr, page_info)) {
        return 0;
    }
    if ((page_info.State & MEM_COMMIT) == 0) {
        return 0;
    }
    size_t region_size = _fetch_region_size(page_info, start_addr);
    if (region_size == 0) {
        return 0;
    }

    const size_t size_to_read = (region_size > buffer_size) ? buffer_size : region_size;

    const bool is_accessible = (page_info.Protect & PAGE_NOACCESS) == 0;
    BOOL access_changed = FALSE;
    DWORD oldProtect = 0;

    // check the access right and eventually try to change it
    if (force_access && !is_accessible) {
        access_changed = VirtualProtectEx(processHandle, start_addr, region_size, PAGE_READONLY, &oldProtect);
#ifdef _DEBUG
        if (!access_changed) {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED) {
                std::cerr << "[!] " << std::hex << start_addr << " : " << region_size << " inaccessible area, changing page access failed: " << std::dec << err << "\n";
            }
        }
#endif
    }

    size_t size_read = 0;
    if (is_accessible || access_changed) {
        size_read = peconv::read_remote_memory(processHandle, start_addr, buffer, size_to_read, minimal_size);
        if ((size_read == 0) && (page_info.Protect & PAGE_GUARD)) {
#ifdef _DEBUG
            std::cout << "Warning: guarded page, trying to read again..." << std::endl;
#endif
            size_read = peconv::read_remote_memory(processHandle, start_addr, buffer, size_to_read, minimal_size);
        }
    }
    // if the access rights were changed, change it back:
    if (access_changed) {
        VirtualProtectEx(processHandle, start_addr, region_size, oldProtect, &oldProtect);
    }
    return size_read;
}

size_t peconv::read_remote_area(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const bool force_access, const SIZE_T minimal_size)
{
    if (!buffer || !start_addr || buffer_size == 0) {
        return 0;
    }
    memset(buffer, 0, buffer_size);

    size_t real_read = 0; //how many bytes has been realy read (not counting the skipped areas)
    size_t total_read = 0;
    for (total_read = 0; total_read < buffer_size; ) {
        LPVOID remote_chunk = LPVOID((ULONG_PTR)start_addr + total_read);

        MEMORY_BASIC_INFORMATION page_info = { 0 };
        if (!peconv::fetch_region_info(processHandle, remote_chunk, page_info)) {
            break;
        }
        const size_t region_size = _fetch_region_size(page_info, remote_chunk);
        if (region_size == 0) {
            break;
        }

        // read the memory:
        const size_t read_chunk = read_remote_region(processHandle, remote_chunk, buffer + total_read, buffer_size - total_read, force_access, minimal_size);
        if (read_chunk == 0) {
            //skip the region that could not be read:
            total_read += region_size;
            continue;
        }
        real_read += read_chunk;
        total_read += read_chunk;
    }
    if (real_read == 0) {
        return 0;
    }
    return total_read;
}

bool peconv::read_remote_pe_header(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size)
{
    if (buffer == nullptr) {
        return false;
    }
    SIZE_T read_size = read_remote_memory(processHandle, start_addr, buffer, buffer_size);
    if (read_size == 0) {
        return false;
    }
    BYTE *nt_ptr = get_nt_hdrs(buffer, buffer_size);
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

peconv::UNALIGNED_BUF peconv::get_remote_pe_section(HANDLE processHandle, LPVOID start_addr, const size_t section_num, OUT size_t &section_size, bool roundup, bool force_access)
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
    size_t read_size = peconv::read_remote_memory(processHandle, LPVOID((ULONG_PTR)start_addr + section_hdr->VirtualAddress), module_code, buffer_size);
    if (read_size == 0) {
        // this function is slower, so use it only if the normal read has failed:
        read_size = read_remote_area(processHandle, LPVOID((ULONG_PTR)start_addr + section_hdr->VirtualAddress), module_code, buffer_size, force_access);
    }
    if (read_size == 0) {
        peconv::free_unaligned(module_code);
        return NULL;
    }
    section_size = buffer_size;
    return module_code;
}

size_t peconv::read_remote_pe(const HANDLE processHandle, LPVOID start_addr, const size_t mod_size, OUT BYTE* buffer, const size_t bufferSize)
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
        if (sec_vsize > 0 && !read_remote_memory(processHandle, LPVOID((ULONG_PTR)start_addr + sec_va), buffer + sec_va, sec_vsize)) {
            std::cerr << "[-] Failed to read the module section " << i <<" : at: " << std::hex << (ULONG_PTR)start_addr + sec_va << std::endl;
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

DWORD peconv::get_remote_image_size(IN const HANDLE processHandle, IN LPVOID start_addr)
{
    BYTE hdr_buffer[MAX_HEADER_SIZE] = { 0 };
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        return 0;
    }
    return peconv::get_image_size(hdr_buffer);
}

bool peconv::dump_remote_pe(IN const char *out_path, 
    IN const HANDLE processHandle, 
    IN LPVOID start_addr,
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

