#include "peconv/file_util.h"
#include "peconv/buffer_util.h"

#include <fstream>
#ifdef _DEBUG
    #include <iostream>
#endif

//load file content using MapViewOfFile
peconv::ALIGNED_BUF peconv::load_file(const char *filename, OUT size_t &read_size)
{
    HANDLE file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Could not open file!" << std::endl;
#endif
        return nullptr;
    }
    HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
#ifdef _DEBUG
        std::cerr << "Could not create mapping!" << std::endl;
#endif
        CloseHandle(file);
        return nullptr;
    }
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (dllRawData == nullptr) {
#ifdef _DEBUG
        std::cerr << "Could not map view of file" << std::endl;
#endif
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    size_t r_size = GetFileSize(file, 0);
    if (read_size != 0 && read_size <= r_size) {
        r_size = read_size;
    }
    peconv::ALIGNED_BUF localCopyAddress = peconv::alloc_aligned(r_size, PAGE_READWRITE);
    if (localCopyAddress != nullptr) {
        memcpy(localCopyAddress, dllRawData, r_size);
        read_size = r_size;
    } else {
        read_size = 0;
#ifdef _DEBUG
        std::cerr << "Could not allocate memory in the current process" << std::endl;
#endif
    }
    UnmapViewOfFile(dllRawData);
    CloseHandle(mapping);
    CloseHandle(file);
    return localCopyAddress;
}

//load file content using ReadFile
peconv::ALIGNED_BUF peconv::read_from_file(const char *in_path, size_t &read_size)
{
    HANDLE file = CreateFileA(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for reading!" << std::endl;
#endif
        return nullptr;
    }
    size_t r_size = static_cast<size_t>(GetFileSize(file, 0));
    if (read_size != 0 && read_size <= r_size) {
        r_size = read_size;
    }
    PBYTE buffer = peconv::alloc_pe_buffer(r_size, PAGE_READWRITE);
    if (buffer == nullptr) {
#ifdef _DEBUG
        std::cerr << "Allocation has failed!" << std::endl;
#endif
        return nullptr;
    }
    DWORD out_size = 0;
    if (!ReadFile(file, buffer, r_size, &out_size, nullptr)) {
#ifdef _DEBUG
        std::cerr << "Reading failed!" << std::endl;
#endif
        peconv::free_pe_buffer(buffer, r_size);
        buffer = nullptr;
        read_size = 0;
    } else {
        read_size = r_size;
    }
    CloseHandle(file);
    return buffer;
}

//save the given buffer into a file
bool peconv::dump_to_file(const char *out_path, PBYTE dump_data, size_t dump_size)
{
    HANDLE file = CreateFileA(out_path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for writing!" << std::endl;
#endif
        return false;
    }
    DWORD written_size = 0;
    bool is_dumped = false;
    if (WriteFile(file, dump_data, (DWORD) dump_size, &written_size, nullptr)) {
        is_dumped = true;
    }
#ifdef _DEBUG
    else {
        std::cerr << "Failed to write to the file : " << out_path << std::endl;
    }
#endif
    CloseHandle(file);
    return is_dumped;
}

//free the buffer allocated by load_file/read_from_file
void peconv::free_file(BYTE* buffer)
{
    peconv::free_aligned(buffer);
}
