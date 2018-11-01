#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "pe_virtual_to_raw.h"
#include "exports_mapper.h"
#include "pe_dumper.h"

namespace peconv {

    /**
    Wrapper over ReadProcessMemory. If reading full buffer_size was not possible, it will keep trying to read smaller chunk,
    decreasing requested size by step_size in each iteration. Returns how many bytes were successfuly read.
    It is a workaround for errors such as FAULTY_HARDWARE_CORRUPTED_PAGE.
    */
    size_t read_remote_memory(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size, const SIZE_T step_size = 0x100);

    /**
    Reads a PE header of the remote module within the given process. Requires a valid output buffer to be supplied (buffer).
    */
    bool read_remote_pe_header(HANDLE processHandle, BYTE *moduleBase, OUT BYTE* buffer, const size_t bufferSize);

    /**
    Reads a PE section with a given number (sectionNum) from the remote module within the given process. 
    It returns a buffer containing a copy of the section. 
    The buffer of appropriate size is automatically allocated. After use, it should be freed by the function free_pe_section.
    The size of the buffer is writen into sectionSize.
    */
    BYTE* get_remote_pe_section(HANDLE processHandle, BYTE *moduleBase, const size_t sectionNum, OUT size_t &sectionSize);

    /**
    Reads PE file from the remote process into the supplied buffer. It expects the module base and size to be given.
    */
    size_t read_remote_pe(const HANDLE processHandle, BYTE *moduleBase, const size_t moduleSize, OUT BYTE* buffer, const size_t bufferSize);


    /**
    Dumps PE from the remote process into a file. It expects the module base and size to be given.
    dump_mode: specifies in which format the PE should be dumped. Default: PE_DUMP_UNMAPPED
    exportsMap: optional. If exportsMap is supplied, it will try to recover destroyed import table of the PE, basing on the supplied map of exported functions.
    */
    bool dump_remote_pe(const char *outputFilePath, 
                        const HANDLE processHandle, 
                        BYTE *moduleBase, 
                        t_pe_dump_mode dump_mode = PE_DUMP_UNMAPPED,
                        peconv::ExportsMapper* exportsMap = nullptr
                        );

    DWORD get_remote_image_size(const HANDLE processHandle, BYTE *start_addr);

}; //namespace peconv
