#pragma once

#include <Windows.h>
#include "buffer_util.h"

namespace peconv {

const ULONGLONG MAX_HEADER_SIZE = 0x1000;

DWORD get_image_size(const BYTE *payload);

WORD get_nt_hdr_architecture(const BYTE *pe_buffer);

bool is64bit(const BYTE *pe_buffer);

//if buffer_size=0 means size unknown
BYTE* get_nt_hrds(const BYTE *pe_buffer, size_t buffer_size=0);

IMAGE_NT_HEADERS32* get_nt_hrds32(const BYTE *pe_buffer);
IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE *pe_buffer);

LPVOID get_optional_hdr(const BYTE* payload, const size_t buffer_size);
const IMAGE_FILE_HEADER* get_file_hdr(const BYTE* payload, const size_t buffer_size);

DWORD get_hdrs_size(const BYTE *pe_buffer);

IMAGE_DATA_DIRECTORY* get_directory_entry(const BYTE* pe_buffer, DWORD dir_id);

template <typename IMAGE_TYPE_DIRECTORY>
IMAGE_TYPE_DIRECTORY* get_type_directory(HMODULE modulePtr, DWORD dir_id);

IMAGE_EXPORT_DIRECTORY* get_export_directory(HMODULE modulePtr);

ULONGLONG get_image_base(const BYTE *pe_buffer);

//set a new image base in headers
bool update_image_base(BYTE* payload, ULONGLONG destImageBase);

DWORD get_entry_point_rva(const BYTE *pe_buffer);
bool update_entry_point_rva(BYTE *pe_buffer, DWORD ep);

size_t get_sections_count(const BYTE* buffer, const size_t buffer_size);

//Checks if the section headers are reachable. It does not validate sections alignment.
bool is_valid_sections_hdr(BYTE* buffer, const size_t buffer_size);

PIMAGE_SECTION_HEADER get_section_hdr(const BYTE* buffer, const size_t buffer_size, size_t section_num);

bool is_module_dll(const BYTE* payload);

bool set_subsystem(BYTE* payload, WORD subsystem);

WORD get_subsystem(const BYTE* payload);

bool has_relocations(BYTE *pe_buffer);

IMAGE_COR20_HEADER* get_dotnet_hdr(PBYTE module, size_t module_size, IMAGE_DATA_DIRECTORY* dotNetDir);

}; // namespace peconv
