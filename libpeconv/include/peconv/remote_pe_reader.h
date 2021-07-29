/**
* @file
* @brief   Reading from a PE module that is loaded within a remote process.
*/

#pragma once

#include <windows.h>

#include "pe_hdrs_helper.h"
#include "pe_virtual_to_raw.h"
#include "exports_mapper.h"
#include "pe_dumper.h"

namespace peconv {

    bool fetch_region_info(HANDLE processHandle, LPVOID start_addr, MEMORY_BASIC_INFORMATION &page_info);

    /**
    Fetch size of the memory region starting from the given address.
    */
    size_t fetch_region_size(HANDLE processHandle, LPVOID start_addr);

    /**
    Fetch the allocation base of the memory region with the supplied start address.
    \param processHandle : handle of the process where the region of interest belongs
    \param start_addr : the address inside the region of interest
    \return the allocation base address of the memory region, or 0 if not found
    */
    ULONGLONG fetch_alloc_base(HANDLE processHandle, LPVOID start_addr);

    /**
    Wrapper over ReadProcessMemory. Requires a handle with privilege PROCESS_VM_READ.
    If reading full buffer_size was not possible, it will keep trying to read a smaller chunk,
    decreasing requested size by step_size in each iteration. Returns how many bytes were successfuly read.
    It is a workaround for errors such as FAULTY_HARDWARE_CORRUPTED_PAGE. 
    \param processHandle : handle of the process where the memory of interest belongs
    \param start_addr : the address within the remote process to start reading from
    \param buffer : the buffer where the read data will be stored
    \param buffer_size : the size of the buffer, and the size that will be attempted to read
    \param step_size : the size by which the demanded size will be decreased in each read attempt
    \return the number of bytes successfuly read
    */
    size_t read_remote_memory(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size = 0x100);

    /**
    Reads a single memory region (continuous, with the same access rights) within a given process, starting at the start_addr.
    In case if it is inaccessible, it tries to force the access, or skip.
    Requires a handle with privilege PROCESS_QUERY_INFORMATION.
    step_size is passed to the underlying read_remote_memory.
    */
    size_t read_remote_region(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size = 0x100);

    /**
    Reads the full memory area of a given size within a given process, starting at the start_addr.
    The memory area can consist of multiple regions with various access rights. In case of inaccessible regions, it tries to force the access, or skip.
    Requires a handle with privilege PROCESS_QUERY_INFORMATION.
    step_size is passed to the underlying read_remote_memory.
    */
    size_t read_remote_area(HANDLE processHandle, LPVOID start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size = 0x100);

    /**
    Reads a PE header of the remote module within the given process. Requires a valid output buffer to be supplied (buffer).
    */
    bool read_remote_pe_header(HANDLE processHandle, LPVOID moduleBase, OUT BYTE* buffer, const size_t bufferSize);

    /**
    Reads a PE section with a given number (sectionNum) from the remote module within the given process. 
    The buffer of appropriate size is automatically allocated. After use, it should be freed by the function free_unaligned.
    The size of the buffer is writen into sectionSize.
    \param processHandle : the handle to the remote process
    \param moduleBase : the base address of the module
    \param sectionNum : number of the section to be read
    \param sectionSize : the size of the read section (output)
    \param roundup : if set, the section size is roundup to the alignment unit
    \return a buffer containing a copy of the section.
    */
    peconv::UNALIGNED_BUF get_remote_pe_section(HANDLE processHandle, LPVOID moduleBase, const size_t sectionNum, OUT size_t &sectionSize, bool roundup = false);

    /**
    Reads PE file from the remote process into the supplied buffer. It expects the module base and size to be given.
    */
    size_t read_remote_pe(const HANDLE processHandle, LPVOID moduleBase, const size_t moduleSize, OUT BYTE* buffer, const size_t bufferSize);

    /**
    Dumps PE from the remote process into a file. It expects the module base and size to be given.
    \param outputFilePath : the path where the dump will be saved
    \param processHandle : the handle to the remote process
    \param moduleBase : the base address of the module that needs to be dumped
    \param dump_mode : specifies in which format the PE should be dumped. If the mode was set to PE_DUMP_AUTO, it autodetects mode and returns the detected one.
    \param exportsMap : optional. If exportsMap is supplied, it will try to recover destroyed import table of the PE, basing on the supplied map of exported functions.
    */
    bool dump_remote_pe(
        IN const char *outputFilePath,
        IN const HANDLE processHandle, 
        IN LPVOID moduleBase,
        IN OUT t_pe_dump_mode &dump_mode,
        IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr
    );

    /**
    Retrieve the Image Size saved in the header of the remote PE.
    \param processHandle : process from where we are reading
    \param start_addr : a base address of the PE within the given process
    */
    DWORD get_remote_image_size(IN const HANDLE processHandle, IN LPVOID start_addr);

}; //namespace peconv
