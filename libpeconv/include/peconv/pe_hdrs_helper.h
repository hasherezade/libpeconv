/**
* @file
* @brief   Wrappers over various fields in the PE header. Read, write, parse PE headers.
*/

#pragma once

#include <windows.h>
#include "buffer_util.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

namespace peconv {
    /**
    Maximal size of the PE header.
    */
    const ULONGLONG MAX_HEADER_SIZE = PAGE_SIZE;

    /**
    Fetch image size from headers.
    */
    DWORD get_image_size(IN const BYTE *payload);

    /**
    Change the Image Size in Optional Header to the given one.
    */
    bool update_image_size(IN OUT BYTE* payload, IN DWORD new_img_size);

    /**
    Fetch architecture from the NT headers. Checks for bad pointers. 
    */
    WORD get_nt_hdr_architecture(IN const BYTE *pe_buffer);

    /**
    Wrapper for get_nt_hdr_architecture. Returns true if the PE file is 64 bit.
    */
    bool is64bit(IN const BYTE *pe_buffer);

    /**
    Fetch pointer to the NT headers of the PE file. 
    Checks for bad pointers. If buffer_size is set, validates pointers against the buffer size.
    */
    BYTE* get_nt_hdrs(
        IN const BYTE *pe_buffer, 
        IN OPTIONAL size_t buffer_size=0 //if buffer_size=0 means size unknown
    );

    /**
    Wrapper for get_nt_headers. Automatically detects if the PE is 32 bit - if not, returns null pointer.
    */
    IMAGE_NT_HEADERS32* get_nt_hdrs32(IN const BYTE *pe_buffer);

    /**
    Wrapper for get_nt_headers. Automatically detects if the PE is 64 bit - if not, returns null pointer.
    */
    IMAGE_NT_HEADERS64* get_nt_hdrs64(IN const BYTE *pe_buffer);

    /**
    Fetches optional header of the PE. Validates pointers against buffer size.
    */
    LPVOID get_optional_hdr(IN const BYTE* payload, IN const size_t buffer_size);

    /**
    Fetches file header of the PE. Validates pointers against buffer size.
    */
    const IMAGE_FILE_HEADER* get_file_hdr(
        IN const BYTE* payload,
        IN const size_t buffer_size
    );

    /**
    Fetch the size of headers (from Optional Header).
    */
    DWORD get_hdrs_size(IN const BYTE *pe_buffer);

    /**
    get Data Directory entry of the given number. If the entry is not filled and allow_empty is not set, it returns null pointer.
    */
    IMAGE_DATA_DIRECTORY* get_directory_entry(IN const BYTE* pe_buffer, IN DWORD dir_id, IN bool allow_empty = false);

    /**
    Get pointer to the Data Directory content of the given number. Automatically cast to the chosen type.
    */
    template <typename IMAGE_TYPE_DIRECTORY>
    IMAGE_TYPE_DIRECTORY* get_type_directory(IN HMODULE modulePtr, IN DWORD dir_id)
    {
        IMAGE_DATA_DIRECTORY *my_dir = peconv::get_directory_entry((const BYTE*)modulePtr, dir_id);
        if (!my_dir) return nullptr;

        DWORD dir_addr = my_dir->VirtualAddress;
        if (dir_addr == 0) return nullptr;

        return (IMAGE_TYPE_DIRECTORY*)(dir_addr + (ULONG_PTR)modulePtr);
    }

    /**
    Get pointer to the Export Directory.
    */
    IMAGE_EXPORT_DIRECTORY* get_export_directory(IN HMODULE modulePtr);

    // Fetch Image Base from Optional Header.
    ULONGLONG get_image_base(IN const BYTE *pe_buffer);

    /**
    Change the Image Base in Optional Header to the given one.
    */
    bool update_image_base(IN OUT BYTE* payload, IN ULONGLONG destImageBase);

    /**
    Get RVA of the Entry Point from the Optional Header.
    */
    DWORD get_entry_point_rva(IN const BYTE *pe_buffer);

    /**
    Change the Entry Point RVA in the Optional Header to the given one.
    */
    bool update_entry_point_rva(IN OUT BYTE *pe_buffer, IN DWORD ep);

    /**
    Get number of sections from the File Header. It does not validate if this the actual number.
    */
    size_t get_sections_count(
        IN const BYTE* buffer,
        IN const size_t buffer_size
    );

    /**
    Checks if the section headers are reachable. It does not validate sections alignment.
    */
    bool is_valid_sections_hdr_offset(IN const BYTE* buffer, IN const size_t buffer_size);

    /**
    Gets pointer to the section header of the given number.
    */
    PIMAGE_SECTION_HEADER get_section_hdr(
        IN const BYTE* pe_buffer,
        IN const size_t buffer_size,
        IN size_t section_num
    );

    /**
    Fetch the PE Characteristics from the File Header.
    */
    WORD get_file_characteristics(IN const BYTE* payload);

    /**
    Check if the module is a DLL (basing on the Characteristcs in the header).
    */
    bool is_module_dll(IN const BYTE* payload);

    /**
    Check if the module is a .NET executable
    */
    bool is_dot_net(BYTE *pe_buffer, size_t pe_buffer_size);

    /**
    Fetch the DLL Characteristics from the Optional Header.
    */
    WORD get_dll_characteristics(IN const BYTE* payload);

    /**
    Set the PE subsystem in the header.
    */
    bool set_subsystem(IN OUT BYTE* payload, IN WORD subsystem);

    /**
    Get the PE subsystem from the header.
    */
    WORD get_subsystem(IN const BYTE* payload);

    /**
    Check if the PE has relocations Data Directory.
    */
    bool has_relocations(IN const BYTE *pe_buffer);

    /**
    Fetch the pointer to the .NET header (if exist).
    */
    IMAGE_COR20_HEADER* get_dotnet_hdr(
        IN const BYTE* pe_buffer,
        IN size_t const buffer_size,
        IN const IMAGE_DATA_DIRECTORY* dotNetDir
    );

    /**
    Fetch section aligmenent from headers. Depending on the flag, it fetches either Raw Alignment or Virtual Alignment.
    */
    DWORD get_sec_alignment(IN const BYTE* modulePtr, IN bool is_raw);

    /**
    Change section aligmenent in headers. Depending on the flag, it sets either Raw Alignment or Virtual Alignment.
    */
    bool set_sec_alignment(IN OUT BYTE* pe_buffer, IN bool is_raw, IN DWORD new_alignment);

    /**
    Get size of virtual section from the headers (optionaly rounds it up to the Virtual Alignment)
    */
    DWORD get_virtual_sec_size(
        IN const BYTE* pe_hdr,
        IN const PIMAGE_SECTION_HEADER sec_hdr,
        IN bool rounded //if set, it rounds it up to the Virtual Alignment
    );

    /**
    Get the last section (in a raw or virtual alignment)
    \param pe_buffer : buffer with a PE
    \param pe_size : size of the given PE
    \param is_raw : If true, give the section with the highest Raw offset. If false, give the section with the highest Virtual offset.
    */
    PIMAGE_SECTION_HEADER get_last_section(IN const PBYTE pe_buffer, IN size_t pe_size, IN bool is_raw);

    /**
    Calculate full PE size (raw or virtual) using information from sections' headers. WARNING: it drops an overlay.
    \param pe_buffer : a buffer containing a PE
    \param pe_size : the size of the given buffer
    \param is_raw : If true, the Raw alignment is used. If false, the Virtual alignment is used.
    */
    DWORD calc_pe_size(
        IN const PBYTE pe_buffer,
        IN size_t pe_size,
        IN bool is_raw
    );

    /**
    Walk through sections headers checking if the sections beginnings and sizes are fitting the alignment (Virtual or Raw)
    \param buffer : a buffer containing a PE
    \param buffer_size : the size of the given buffer
    \param is_raw : If true, the Raw alignment is checked. If false, the Virtual alignment is checked.
    */
    bool is_valid_sectons_alignment(IN const BYTE* buffer, IN const SIZE_T buffer_size, IN bool is_raw);

}; // namespace peconv
