/**
* @file
* @brief   Functions related to operations on files. Wrappers for read/write.
*/

#pragma once

#include <windows.h>
#include <iostream>

#include "buffer_util.h"

namespace peconv {

    /**
    Maps a file with the given path and copies its raw content into the output buffer. 
    If read_size is not zero, it reads maximum read_size of bytes. If read_size is zero, it reads the full file.
    The actual read size is returned back in read_size.
    Automatically allocates a buffer of the required size.
    */
    peconv::ALIGNED_BUF load_file(IN const char *filename, OUT size_t &r_size);

    /**
    Reads a raw content of the file with the given path. 
    If read_size is not zero, it reads maximum read_size of bytes. If read_size is zero, it reads the full file.
    The actual read size is returned back in read_size.
    Automatically allocates a buffer of the required size.
    */
    peconv::ALIGNED_BUF read_from_file(IN const char *path, IN OUT size_t &read_size);

    /**
    Writes a buffer of bytes into a file of given path.
    \param path : the path to the output file
    \param dump_data : the buffer to be dumped
    \param dump_size : the size of data to be dumped (in bytes)
    \return true if succeeded, false if failed
    */
    bool dump_to_file(IN const char *path, IN PBYTE dump_data, IN size_t dump_size);

    /**
    Free the buffer allocated by load_file/read_from_file
    */
    void free_file(IN peconv::ALIGNED_BUF buffer);

    /**
    Get the file name from the given path.
    */
    std::string get_file_name(IN const std::string full_path);

    /**
    Get the directory name from the given path. It assumes that a directory name always ends with a separator ("/" or "\")
    */
    std::string get_directory_name(IN const std::string full_path);

}; //namespace peconv
