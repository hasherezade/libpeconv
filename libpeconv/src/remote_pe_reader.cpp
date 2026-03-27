#include "peconv/remote_pe_reader.h"

#include "peconv/logger.h"

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
        return 0; //invalid type, skip it
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
            if (ReadProcessMemory(processHandle, start_addr, buffer, last_success_size, &read_size)) {
                return read_size;
            }
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
    DWORD last_error = ERROR_SUCCESS;

    SIZE_T read_size = 0;
    if (!ReadProcessMemory(processHandle, start_addr, buffer, buffer_size, &read_size)) {
        last_error = GetLastError();
        if (last_error == ERROR_PARTIAL_COPY) {
            read_size = peconv::_search_readable_size(processHandle, start_addr, buffer, buffer_size, minimal_size);
            LOG_DEBUG("peconv::search_readable_size res: 0x%zx.", read_size);
        }
    }

    if (read_size == 0) {
        LOG_WARNING("Cannot read memory. Last Error: %lu.", last_error);
    } else if (read_size < buffer_size) {
        LOG_WARNING("Read size: 0x%zx is smaller than requested: 0x%zx. Last Error: %lu.", (size_t)read_size, buffer_size, last_error);
    }
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
        if (!access_changed) {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED) {
                LOG_WARNING("0x%llx : 0x%zx inaccessible area, changing page access failed: %lu.", (unsigned long long)(ULONG_PTR)start_addr, region_size, err);
            }
        }
    }

    size_t size_read = 0;
    if (is_accessible || access_changed) {
        size_read = peconv::read_remote_memory(processHandle, start_addr, buffer, size_to_read, minimal_size);
        if ((size_read == 0) && (page_info.Protect & PAGE_GUARD)) {
            LOG_DEBUG("Guarded page, trying to read again.");
            size_read = peconv::read_remote_memory(processHandle, start_addr, buffer, size_to_read, minimal_size);
        }
    }
    // if the access rights were changed, change it back:
    if (access_changed) {
        if (!VirtualProtectEx(processHandle, start_addr, region_size, oldProtect, &oldProtect)) {
            LOG_WARNING("Failed to restore protection of region: %p", start_addr);
        }
    }
    return size_read;
}

size_t peconv::read_remote_area(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const bool force_access, const SIZE_T minimal_size)
{
    if (!buffer || !start_addr || buffer_size == 0) {
        return 0;
    }
    memset(buffer, 0, buffer_size);

    size_t real_read = 0; // how many bytes has been realy read (not counting the skipped areas)
    size_t last_valid = 0; // the last chunk that was really read (don't count the last skipped ones)

    size_t buf_index = 0;
    for (buf_index = 0; buf_index < buffer_size; ) {
        LPVOID remote_chunk = LPVOID((ULONG_PTR)start_addr + buf_index);

        MEMORY_BASIC_INFORMATION page_info = { 0 };
        if (!peconv::fetch_region_info(processHandle, remote_chunk, page_info)) {
            break;
        }
        const size_t region_size = _fetch_region_size(page_info, remote_chunk);
        if (region_size == 0) {
            break;
        }

        // read the memory:
        const size_t read_chunk = read_remote_region(
            processHandle,
            remote_chunk,
            (BYTE*)((ULONG_PTR)buffer + buf_index),
            buffer_size - buf_index,
            force_access,
            minimal_size
        );
        if (read_chunk == 0) {
            //skip the region that could not be read, and proceed to the next:
            buf_index += region_size;
            continue;
        }
        buf_index += read_chunk;
        real_read += read_chunk; // total sum of the read content
        last_valid = buf_index; // the last chunk that was really read
    }
    if (real_read == 0) {
        return 0;
    }
    return last_valid;
}

bool peconv::read_remote_pe_header(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, bool force_access)
{
    if (buffer == nullptr) {
        return false;
    }
    SIZE_T read_size = read_remote_area(processHandle, start_addr, buffer, buffer_size, force_access);
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
        LOG_ERROR("[PID %lu][0x%llx] Read size: 0x%zx is smaller than the minimal size: 0x%lx.", get_process_id(processHandle), (unsigned long long)(ULONGLONG)start_addr, read_size, get_hdrs_size(buffer));
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
        LOG_ERROR("Invalid output buffer: NULL pointer.");
        return 0;
    }
    if (bufferSize < mod_size || bufferSize < MAX_HEADER_SIZE ) {
        LOG_ERROR("Invalid output buffer: size too small.");
        return 0;
    }
    // read PE section by section
    PBYTE hdr_buffer = buffer;
    //try to read headers:
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        LOG_ERROR("Failed to read the module header.");
        return 0;
    }
    if (!is_valid_sections_hdr_offset(hdr_buffer, MAX_HEADER_SIZE)) {
        LOG_ERROR("Section headers are invalid or atypically aligned.");
        return 0;
    }
    size_t sections_count = get_sections_count(hdr_buffer, MAX_HEADER_SIZE);
    LOG_DEBUG("Sections: %zu.", sections_count);
    size_t read_size = MAX_HEADER_SIZE;

    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER hdr = get_section_hdr(hdr_buffer, MAX_HEADER_SIZE, i);
        if (!hdr) {
            LOG_ERROR("Failed to read the header of section: %zu.", i);
            break;
        }
        const DWORD sec_va = hdr->VirtualAddress;
        const DWORD sec_vsize = get_virtual_sec_size(hdr_buffer, hdr, true);
        if (sec_va + sec_vsize > bufferSize) {
            LOG_ERROR("No more space in the buffer.");
            break;
        }
        if (sec_vsize > 0 && !read_remote_memory(processHandle, LPVOID((ULONG_PTR)start_addr + sec_va), buffer + sec_va, sec_vsize)) {
            LOG_WARNING("Failed to read module section %zu at 0x%llx.", i, (unsigned long long)((ULONG_PTR)start_addr + sec_va));
        }
        // update the end of the read area:
        size_t new_end = sec_va + sec_vsize;
        if (new_end > read_size) read_size = new_end;
    }
    LOG_DEBUG("Total read size: %zu.", read_size);
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

bool peconv::dump_remote_pe(
    IN LPCTSTR out_path,
    IN const HANDLE processHandle, 
    IN LPVOID start_addr,
    IN OUT t_pe_dump_mode &dump_mode, 
    IN OPTIONAL peconv::ExportsMapper* exportsMap)
{
    DWORD mod_size = get_remote_image_size(processHandle, start_addr);
    LOG_DEBUG("Module size: %u.", mod_size);
    if (mod_size == 0) {
        return false;
    }
    BYTE* buffer = peconv::alloc_pe_buffer(mod_size, PAGE_READWRITE);
    if (buffer == nullptr) {
        LOG_ERROR("Failed allocating buffer. Error: %lu.", GetLastError());
        return false;
    }
    //read the module that it mapped in the remote process:
    const size_t read_size = read_remote_pe(processHandle, start_addr, mod_size, buffer, mod_size);
    if (read_size == 0) {
        LOG_ERROR("Failed reading module. Error: %lu.", GetLastError());
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

