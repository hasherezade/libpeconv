#include "peconv/util.h"

#include <fstream>
#include <iostream>
#include "peconv/module_helper.h"

bool peconv::validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size)
{
    ULONGLONG start = (ULONGLONG)buffer_bgn;
    ULONGLONG end = start + buffer_size;

    ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

    if ((ULONGLONG)field_bgn < start) {
        return false;
    }
    if (field_end >= end) {
        return false;
    }
    return true;
}

bool peconv::dump_to_file(const char *out_path, PBYTE dump_data, size_t dump_size)
{
    HANDLE file = CreateFile(out_path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot open the file for writing!" << std::endl;
        return false;
    }
    DWORD written_size = 0;
    bool is_dumped = false;
    if (WriteFile(file, dump_data, (DWORD) dump_size, &written_size, nullptr)) {
        is_dumped = true;
    } else {
        std::cerr << "Failed to write to the file : " << out_path << std::endl;
    }
    CloseHandle(file);
    return is_dumped;
}

PBYTE peconv::read_from_file(const char *in_path, size_t &read_size)
{
    HANDLE file = CreateFile(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot open the file for reading!" << std::endl;
        return nullptr;
    }
    size_t r_size = (size_t) GetFileSize(file, 0);
    PBYTE buffer = peconv::alloc_pe_buffer(r_size, PAGE_READWRITE);
    if (buffer == nullptr) {
        //Allocation has failed!
        return nullptr;
    }
    DWORD out_size = 0;
    if (!ReadFile(file, buffer, r_size, &out_size, nullptr)) {
        std::cerr << "Reading failed!" << std::endl;
        peconv::free_pe_buffer(buffer, r_size);
        buffer = nullptr;
        read_size = 0;
    }
    read_size = r_size;
    CloseHandle(file);
    return buffer;
}

