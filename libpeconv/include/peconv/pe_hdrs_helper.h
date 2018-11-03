#pragma once

#include <Windows.h>
#include "buffer_util.h"

namespace peconv {
    const ULONGLONG PAGE_SIZE = 0x1000;
    const ULONGLONG MAX_HEADER_SIZE = PAGE_SIZE;

    // Fetch image size from headers.
    DWORD get_image_size(_In_ const BYTE *payload);

    // Fetch architecture from the NT headers. Checks for bad pointers. 
    WORD get_nt_hdr_architecture(_In_ const BYTE *pe_buffer);

    // Wrapper for get_nt_hdr_architecture. Returns true if the PE file is 64 bit.
    bool is64bit(_In_ const BYTE *pe_buffer);

    // Fetch pointer to the NT headers of the PE file. 
    // Checks for bad pointers. If buffer_size is set, validates pointers against the buffer size.
    BYTE* get_nt_hrds(
        _In_reads_bytes_(buffer_size) const BYTE *pe_buffer, 
        _In_opt_ size_t buffer_size=0 //if buffer_size=0 means size unknown
    );

    // Wrapper for get_nt_headers. Automatically detects if the PE is 32 bit - if not, returns null pointer.
    IMAGE_NT_HEADERS32* get_nt_hrds32(_In_ const BYTE *pe_buffer);

    // Wrapper for get_nt_headers. Automatically detects if the PE is 64 bit - if not, returns null pointer.
    IMAGE_NT_HEADERS64* get_nt_hrds64(_In_ const BYTE *pe_buffer);

    // Fetches optional header of the PE. Validates pointers against buffer size.
    LPVOID get_optional_hdr(_In_reads_bytes_(buffer_size) const BYTE* payload, const size_t buffer_size);

    // Fetches file header of the PE. Validates pointers against buffer size.
    const IMAGE_FILE_HEADER* get_file_hdr(
        _In_reads_bytes_(buffer_size) const BYTE* payload,
        _In_ const size_t buffer_size
    );

    //Fetch the size of headers (from Optional Header).
    DWORD get_hdrs_size(_In_ const BYTE *pe_buffer);

    //get Data Directory entry of the given number. If the entry is not filled, it returns null pointer.
    IMAGE_DATA_DIRECTORY* get_directory_entry(_In_ const BYTE* pe_buffer, _In_ DWORD dir_id);

    // Get pointer to the Data Directory content of the given number. Automatically case to the chosen type.
    template <typename IMAGE_TYPE_DIRECTORY>
    IMAGE_TYPE_DIRECTORY* get_type_directory(_In_ HMODULE modulePtr, _In_ DWORD dir_id);

    // Get pointer to the Export Directory.
    IMAGE_EXPORT_DIRECTORY* get_export_directory(_In_ HMODULE modulePtr);

    // Fetch Image Base from Optional Header.
    ULONGLONG get_image_base(_In_ const BYTE *pe_buffer);

    // Change the Image Base in Optional Header to the given one.
    bool update_image_base(_Inout_ BYTE* payload, _In_ ULONGLONG destImageBase);

    // Get RVA of the Entry Point from the Optional Header.
    DWORD get_entry_point_rva(_In_ const BYTE *pe_buffer);

    // Change the Entry Point RVA in the Optional Header to the given one.
    bool update_entry_point_rva(_Inout_ BYTE *pe_buffer, _In_ DWORD ep);

    // Get number of sections from the File Header. It does not validate if this the actual number.
    size_t get_sections_count(
        _In_reads_bytes_(buffer_size) const BYTE* buffer,
        _In_ const size_t buffer_size
    );

    //Checks if the section headers are reachable. It does not validate sections alignment.
    bool is_valid_sections_hdr(_In_reads_bytes_(buffer_size) const BYTE* buffer, _In_ const size_t buffer_size);

    // Gets pointer to the section header of the given number.
    PIMAGE_SECTION_HEADER get_section_hdr(
        _In_reads_bytes_(buffer_size) const BYTE* pe_buffer,
        _In_ const size_t buffer_size,
        _In_ size_t section_num
    );

    bool is_module_dll(_In_ const BYTE* payload);

    bool set_subsystem(_Inout_ BYTE* payload, _In_ WORD subsystem);

    WORD get_subsystem(_In_ const BYTE* payload);

    bool has_relocations(_In_ const BYTE *pe_buffer);

    IMAGE_COR20_HEADER* get_dotnet_hdr(
        _In_reads_bytes_(buffer_size) const PBYTE pe_buffer,
        _In_ size_t const buffer_size,
        _In_ const IMAGE_DATA_DIRECTORY* dotNetDir
    );

    // Fetch section aligmenent from headers. Depending on the flag, it fetches either Raw Alignment or Virtual Alignment.
    DWORD get_sec_alignment(_In_ const PBYTE modulePtr, _In_ bool is_raw);

    // Change section aligmenent in headers. Depending on the flag, it sets either Raw Alignment or Virtual Alignment.
    bool set_sec_alignment(_Inout_ PBYTE pe_buffer, _In_ bool is_raw, _In_ DWORD new_alignment);

    // Get size of virtual section from the headers (optionaly rounds it up to the Virtual Alignment)
    DWORD get_virtual_sec_size(
        _In_ const BYTE* pe_hdr,
        _In_ const PIMAGE_SECTION_HEADER sec_hdr,
        _In_ bool rounded //if set, it rounds it up to the Virtual Alignment
    );

    // Calculate full PE size (raw or virtual) using information from sections' headers. WARNING: it drops an overlay.
    DWORD calc_pe_size(
        _In_reads_bytes_(pe_size) const PBYTE pe_buffer,
        _In_ size_t pe_size,
        _In_ bool is_raw
    );

}; // namespace peconv
