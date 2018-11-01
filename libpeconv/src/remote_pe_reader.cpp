#include "peconv/remote_pe_reader.h"

#include <iostream>

#include "peconv/util.h"
#include "peconv/fix_imports.h"

using namespace peconv;

size_t peconv::read_remote_memory(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size)
{
    if (buffer == nullptr) {
        return 0;
    }

    memset(buffer, 0, buffer_size);

    SIZE_T read_size = 0;
    SIZE_T to_read_size = buffer_size;

    DWORD last_error = 0;
    while (to_read_size > 0) {
        BOOL is_ok = ReadProcessMemory(processHandle, start_addr, buffer, to_read_size, &read_size);
        if (!is_ok) {
            last_error = GetLastError();

            if (to_read_size < step_size) {
                break;
            } else {
                //try to read less
                to_read_size -= step_size;
                continue;
            }
        }
        if (to_read_size < buffer_size) {
            std::cerr << "[WARNING] Read size: " << std::hex << to_read_size 
                << " is smaller than the requested size: " << std::hex << buffer_size 
                << ". Last Error: " << last_error << std::endl;
        }
        return static_cast<size_t>(to_read_size);
    }
    return 0;
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
    BYTE *nt_ptr = get_nt_hrds(buffer);
    if (nt_ptr == nullptr) {
        return false;
    }
    const size_t nt_offset = nt_ptr - buffer;
    const size_t nt_size = peconv::is64bit(buffer) ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    const size_t min_size = nt_offset + nt_size;

    if (read_size < min_size) {
        std::cerr << "[-] [" << std::dec << GetProcessId(processHandle) 
            << " ][" << std::hex << (ULONGLONG) start_addr 
            << "] Read size: " << std::hex << read_size 
            << " is smaller that the minimal size:" << get_hdrs_size(buffer) 
            << std::endl;
        return false;
    }
    //reading succeeded and the header passed the checks:
    return true;
}

BYTE* peconv::get_remote_pe_section(HANDLE processHandle, BYTE *start_addr, const size_t section_num, OUT size_t &section_size)
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
    BYTE *module_code = peconv::alloc_pe_section(buffer_size);
    if (module_code == NULL) {
        return NULL;
    }
    size_t read_size = read_remote_memory(processHandle, start_addr + section_hdr->VirtualAddress, module_code, buffer_size);
    if (read_size == 0) {
        peconv::free_pe_section(module_code);
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
    
    //first try to read the continuous memory area:
    size_t read_size = read_remote_memory(processHandle, start_addr, buffer, mod_size);
    if (read_size == mod_size) {
        //ok, read full at once:
        return mod_size;
    }
    
    //if not possible to read full module at once, try to read it section by section:

    PBYTE hdr_buffer = buffer;
    if (read_size < MAX_HEADER_SIZE) {
        //try to read headers:
        if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
            std::cerr << "[-] Failed to read the module header" << std::endl;
            return 0;
        }
    }
    if (!is_valid_sections_hdr(hdr_buffer, MAX_HEADER_SIZE)) {
        std::cerr << "[-] Sections headers are invalid or atypically aligned" << std::endl;
        return 0;
    }
    size_t sections_count = get_sections_count(hdr_buffer, MAX_HEADER_SIZE);
#ifdef _DEBUG
    std::cout << "Sections: " << sections_count  << std::endl;
#endif
    read_size = MAX_HEADER_SIZE;

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
            std::cerr << "[-] Failed to read the module section: " << i  << std::endl;
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

DWORD peconv::get_remote_image_size(const HANDLE processHandle, BYTE *start_addr)
{
    BYTE hdr_buffer[MAX_HEADER_SIZE] = { 0 };
    if (!read_remote_pe_header(processHandle, start_addr, hdr_buffer, MAX_HEADER_SIZE)) {
        return 0;
    }
    return peconv::get_image_size(hdr_buffer);
}

t_pe_dump_mode _detect_mode(BYTE* buffer, size_t mod_size)
{
    t_pe_dump_mode dump_mode = peconv::PE_DUMP_UNMAPPED;
    if (peconv::is_pe_raw(buffer, mod_size)) {
        std::cout << "Mode set: Virtual (no unmap)" << std::endl;
        return peconv::PE_DUMP_VIRTUAL;
    }
    if (peconv::is_pe_expanded(buffer, mod_size)) {
        std::cout << "Mode set: Realigned" << std::endl;
        return peconv::PE_DUMP_REALIGNED;
    }
    std::cout << "Mode set: Unmapped" << std::endl;
    return peconv::PE_DUMP_UNMAPPED;
}

bool peconv::dump_pe(const char *out_path,
    BYTE *buffer, size_t mod_size,
    ULONGLONG start_addr,
    t_pe_dump_mode dump_mode,
    peconv::ExportsMapper* exportsMap
)
{
    // if the exportsMap is supplied, attempt to recover the (destroyed) import table:
    if (exportsMap != nullptr) {
        if (!peconv::fix_imports(buffer, mod_size, *exportsMap)) {
            std::cerr << "Unable to fix imports!" << std::endl;
        }
    }
    if (dump_mode == PE_DUMP_AUTO) {
        dump_mode = _detect_mode(buffer, mod_size);
    }

    BYTE* dump_data = buffer;
    size_t dump_size = mod_size;
    size_t out_size = 0;
    BYTE* unmapped_module = nullptr;

    if (dump_mode == peconv::PE_DUMP_UNMAPPED || dump_mode == peconv::PE_DUMP_REALIGNED) {
        //if the image base in headers is invalid, set the current base and prevent from relocating PE:
        if (peconv::get_image_base(buffer) == 0) {
            peconv::update_image_base(buffer, (ULONGLONG)start_addr);
        }
        if (dump_mode == peconv::PE_DUMP_UNMAPPED) {
            unmapped_module = pe_virtual_to_raw(buffer, mod_size, (ULONGLONG)start_addr, out_size, false);
        }
        else if (dump_mode == peconv::PE_DUMP_REALIGNED) {
            unmapped_module = peconv::pe_realign_raw_to_virtual(buffer, mod_size, (ULONGLONG)start_addr, out_size);
        }
        // unmap the PE file (convert from the Virtual Format into Raw Format)
        if (unmapped_module) {
            dump_data = unmapped_module;
            dump_size = out_size;
        }
    }
    // save the read module into a file
    bool is_dumped = dump_to_file(out_path, dump_data, dump_size);

    peconv::free_pe_buffer(unmapped_module, mod_size);
    return is_dumped;
}

bool peconv::dump_remote_pe(const char *out_path, const HANDLE processHandle, BYTE* start_addr, t_pe_dump_mode dump_mode, peconv::ExportsMapper* exportsMap)
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
    //read the module that it mapped in the remote process:
    if ((read_size = read_remote_pe(processHandle, start_addr, mod_size, buffer, mod_size)) == 0) {
        std::cerr << "[-] Failed reading module. Error: " << GetLastError() << std::endl;
        peconv::free_pe_buffer(buffer, mod_size);
        buffer = nullptr;
        return false;
    }

    bool is_dumped = peconv::dump_pe(out_path,
        buffer, mod_size,
        reinterpret_cast<ULONGLONG>(start_addr),
        dump_mode, exportsMap);

    peconv::free_pe_buffer(buffer, mod_size);
    buffer = nullptr;
    return is_dumped;
}

bool peconv::is_pe_raw(const BYTE* pe_buffer, size_t pe_size)
{
    const size_t v_align = peconv::get_sec_alignment((PBYTE)pe_buffer, false);

    //walk through sections and check their sizes
    size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    if (sections_count == 0) return false;
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(pe_buffer, pe_size, i);
        if (sec->PointerToRawData == 0 || sec->SizeOfRawData == 0) {
            continue; // check next
        }
        if (sec->PointerToRawData >= v_align) continue;

        size_t diff = v_align - sec->PointerToRawData;
        BYTE* sec_raw_ptr = (BYTE*)((ULONGLONG)pe_buffer + sec->PointerToRawData);
        if (!peconv::validate_ptr((const LPVOID)pe_buffer, pe_size, sec_raw_ptr, diff)) {
            return false;
        }
        if (!is_padding(sec_raw_ptr, diff, 0)) {
            //this is not padding: non-zero content detected
            return true;
        }
    }
    return false;
}

bool peconv::is_pe_expanded(const BYTE* pe_buffer, size_t pe_size)
{
    //walk through sections and check their sizes
    size_t sections_count = peconv::get_sections_count(pe_buffer, pe_size);
    for (size_t i = 0; i < sections_count; i++) {
        PIMAGE_SECTION_HEADER sec = peconv::get_section_hdr(pe_buffer, pe_size, i);
        //scan only executable sections
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            if (is_section_expanded(pe_buffer, pe_size, sec)) return true;
        }
    }
    return false;
}

bool peconv::is_section_expanded(const BYTE* pe_buffer, size_t pe_size, PIMAGE_SECTION_HEADER sec)
{
    if (!sec) return false;

    size_t sec_vsize = peconv::get_virtual_sec_size(pe_buffer, sec, true);
    size_t sec_rsize = sec->SizeOfRawData;

    if (sec_rsize >= sec_vsize) return false;
    size_t diff = sec_vsize - sec_rsize;

    BYTE* sec_raw_end_ptr = (BYTE*)((ULONGLONG)pe_buffer + sec->VirtualAddress + sec_rsize);
    if (!peconv::validate_ptr((const LPVOID)pe_buffer, pe_size, sec_raw_end_ptr, diff)) {
        return false;
    }
    if (!is_padding(sec_raw_end_ptr, diff, 0)) {
        //this is not padding: non-zero content detected
        return true;
    }
    return false;
}

