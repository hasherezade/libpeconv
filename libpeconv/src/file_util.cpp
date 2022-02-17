#include "peconv/file_util.h"
#include "peconv/buffer_util.h"
#include "peconv/util.h"

#include <fstream>
#ifdef _DEBUG
    #include <iostream>
#endif

//load file content using MapViewOfFile
peconv::ALIGNED_BUF peconv::load_file(IN LPCTSTR filename, OUT size_t &read_size)
{
    HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
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
    if (!dllRawData) {
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
    if (peconv::is_bad_read_ptr(dllRawData, r_size)) {
        std::cerr << "[-] Mapping of " << filename << " is invalid!" << std::endl;
        UnmapViewOfFile(dllRawData);
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    peconv::UNALIGNED_BUF localCopyAddress = peconv::alloc_unaligned(r_size);
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
peconv::ALIGNED_BUF peconv::read_from_file(IN LPCTSTR in_path, IN OUT size_t &read_size)
{
    HANDLE file = CreateFile(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for reading!" << std::endl;
#endif
        return nullptr;
    }
    DWORD r_size = GetFileSize(file, 0);
    if (read_size != 0 && read_size <= r_size) {
        r_size = MASK_TO_DWORD(read_size);
    }
    peconv::UNALIGNED_BUF buffer = peconv::alloc_unaligned(r_size);
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
        peconv::free_file(buffer);
        buffer = nullptr;
        read_size = 0;
    } else {
        read_size = r_size;
    }
    CloseHandle(file);
    return buffer;
}

//save the given buffer into a file
bool peconv::dump_to_file(IN LPCTSTR out_path, IN PBYTE dump_data, IN size_t dump_size)
{
    if (!out_path || !dump_data || !dump_size) return false;

    HANDLE file = CreateFile(out_path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
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
void peconv::free_file(IN peconv::UNALIGNED_BUF buffer)
{
    peconv::free_unaligned(buffer);
}

std::string peconv::get_file_name(IN const std::string str)
{
    size_t found = str.find_last_of("/\\");
    if (found == std::string::npos) {
        return str;
    }
    return str.substr(found + 1);
}

std::string peconv::get_directory_name(IN const std::string str)
{
    size_t found = str.find_last_of("/\\");
    if (found == std::string::npos) {
        return "";
    }
    return str.substr(0, found);
}

size_t peconv::find_extension_pos(IN const std::string str)
{
    size_t len = str.length();
    size_t ext_pos = len;
    for (size_t k = len; k != 0; k--) {
        size_t i = k - 1;
        char c = str[i];
        if (c == '.') {
            ext_pos = i;
            break;
        }
    }
    return ext_pos;
}
