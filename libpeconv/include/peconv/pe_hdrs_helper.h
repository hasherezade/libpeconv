#pragma once

#include <Windows.h>
#include "buffer_util.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

namespace peconv {
    const ULONGLONG MAX_HEADER_SIZE = PAGE_SIZE;

    // Fetch image size from headers.
    DWORD get_image_size(IN const BYTE *payload);

    // Change the Image Base in Optional Header to the given one.
    bool update_image_size(IN OUT BYTE* payload, IN DWORD destImageBase);

    // Fetch architecture from the NT headers. Checks for bad pointers. 
    WORD get_nt_hdr_architecture(IN const BYTE *pe_buffer);

    // Wrapper for get_nt_hdr_architecture. Returns true if the PE file is 64 bit.
    bool is64bit(IN const BYTE *pe_buffer);

    // Fetch pointer to the NT headers of the PE file. 
    // Checks for bad pointers. If buffer_size is set, validates pointers against the buffer size.
    BYTE* get_nt_hrds(
        IN const BYTE *pe_buffer, 
        IN OPTIONAL size_t buffer_size=0 //if buffer_size=0 means size unknown
    );

    // Wrapper for get_nt_headers. Automatically detects if the PE is 32 bit - if not, returns null pointer.
    IMAGE_NT_HEADERS32* get_nt_hrds32(IN const BYTE *pe_buffer);

    // Wrapper for get_nt_headers. Automatically detects if the PE is 64 bit - if not, returns null pointer.
    IMAGE_NT_HEADERS64* get_nt_hrds64(IN const BYTE *pe_buffer);

    // Fetches optional header of the PE. Validates pointers against buffer size.
    LPVOID get_optional_hdr(IN const BYTE* payload, IN const size_t buffer_size);

    // Fetches file header of the PE. Validates pointers against buffer size.
    const IMAGE_FILE_HEADER* get_file_hdr(
        IN const BYTE* payload,
        IN const size_t buffer_size
    );

    //Fetch the size of headers (from Optional Header).
    DWORD get_hdrs_size(IN const BYTE *pe_buffer);

    //get Data Directory entry of the given number. If the entry is not filled and allow_empty is not set, it returns null pointer.
    IMAGE_DATA_DIRECTORY* get_directory_entry(IN const BYTE* pe_buffer, IN DWORD dir_id, IN bool allow_empty = false);

    // Get pointer to the Data Directory content of the given number. Automatically case to the chosen type.
    template <typename IMAGE_TYPE_DIRECTORY>
    IMAGE_TYPE_DIRECTORY* get_type_directory(IN HMODULE modulePtr, IN DWORD dir_id);

    // Get pointer to the Export Directory.
    IMAGE_EXPORT_DIRECTORY* get_export_directory(IN HMODULE modulePtr);

    // Fetch Image Base from Optional Header.
    ULONGLONG get_image_base(IN const BYTE *pe_buffer);

    // Change the Image Base in Optional Header to the given one.
    bool update_image_base(IN OUT BYTE* payload, IN ULONGLONG destImageBase);

    // Get RVA of the Entry Point from the Optional Header.
    DWORD get_entry_point_rva(IN const BYTE *pe_buffer);

    // Change the Entry Point RVA in the Optional Header to the given one.
    bool update_entry_point_rva(IN OUT BYTE *pe_buffer, IN DWORD ep);

    // Get number of sections from the File Header. It does not validate if this the actual number.
    size_t get_sections_count(
        IN const BYTE* buffer,
        IN const size_t buffer_size
    );

    //Checks if the section headers are reachable. It does not validate sections alignment.
    bool is_valid_sections_hdr_offset(IN const BYTE* buffer, IN const size_t buffer_size);

    // Gets pointer to the section header of the given number.
    PIMAGE_SECTION_HEADER get_section_hdr(
        IN const BYTE* pe_buffer,
        IN const size_t buffer_size,
        IN size_t section_num
    );

    WORD get_file_characteristics(IN const BYTE* payload);

    bool is_module_dll(IN const BYTE* payload);

    WORD get_dll_characteristics(IN const BYTE* payload);

    bool set_subsystem(IN OUT BYTE* payload, IN WORD subsystem);

    WORD get_subsystem(IN const BYTE* payload);

    bool has_relocations(IN const BYTE *pe_buffer);

    IMAGE_COR20_HEADER* get_dotnet_hdr(
        IN const BYTE* pe_buffer,
        IN size_t const buffer_size,
        IN const IMAGE_DATA_DIRECTORY* dotNetDir
    );

    // Fetch section aligmenent from headers. Depending on the flag, it fetches either Raw Alignment or Virtual Alignment.
    DWORD get_sec_alignment(IN const BYTE* modulePtr, IN bool is_raw);

    // Change section aligmenent in headers. Depending on the flag, it sets either Raw Alignment or Virtual Alignment.
    bool set_sec_alignment(IN OUT BYTE* pe_buffer, IN bool is_raw, IN DWORD new_alignment);

    // Get size of virtual section from the headers (optionaly rounds it up to the Virtual Alignment)
    DWORD get_virtual_sec_size(
        IN const BYTE* pe_hdr,
        IN const PIMAGE_SECTION_HEADER sec_hdr,
        IN bool rounded //if set, it rounds it up to the Virtual Alignment
    );

    // Calculate full PE size (raw or virtual) using information from sections' headers. WARNING: it drops an overlay.
    DWORD calc_pe_size(
        IN const PBYTE pe_buffer,
        IN size_t pe_size,
        IN bool is_raw
    );

    bool is_valid_sectons_alignment(IN const BYTE* payload, IN const SIZE_T payload_size, IN bool is_raw);

}; // namespace peconv
