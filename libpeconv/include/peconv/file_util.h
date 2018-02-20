#pragma once

#include <windows.h>
#include "module_helper.h"

namespace peconv {

    /**
    Maps a file with the given path and copies its raw content into the output buffer. 
    If read_size is not zero, it reads maximum read_size of bytes. If read_size is zero, it reads the full file.
    The actual read size is returned back in read_size.
    Automatically allocates a buffer of the required size.
    */
    peconv::ALIGNED_BUF load_file(const char *filename, OUT size_t &r_size);

    /**
    Reads a raw content of the file with the given path. 
    If read_size is not zero, it reads maximum read_size of bytes. If read_size is zero, it reads the full file.
    The actual read size is returned back in read_size.
    Automatically allocates a buffer of the required size.
    */
    peconv::ALIGNED_BUF read_from_file(IN const char *path, IN OUT size_t &read_size);

    // Writes a buffer of bytes into a file of given path
    bool dump_to_file(OUT const char *path, IN PBYTE dump_data, IN size_t dump_size);

    //free the buffer allocated by load_file/read_from_file
    void free_file(IN peconv::ALIGNED_BUF buffer);

}; //namespace peconv
