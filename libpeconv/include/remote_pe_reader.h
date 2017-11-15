#pragma once

#include <Windows.h>

#include "pe_hdrs_helper.h"
#include "pe_virtual_to_raw.h"

/**
Reads a PE header of the remote module within the given process. Requires a valid output buffer to be supplied (buffer).
*/
bool read_remote_pe_header(HANDLE processHandle, BYTE *moduleBase, size_t moduleSize, OUT BYTE* buffer, const size_t bufferSize);

/**
Reads a PE section with a given number (sectionNum) from the remote module within the given process. 
It returns a buffer containing a copy of the section. 
The buffer of appropriate size is automatically allocated. After use, it should be freed by the function free_remote_module_section.
The size of the buffer is writen into sectionSize.
*/
BYTE* get_remote_pe_section(HANDLE processHandle, BYTE *moduleBase, size_t moduleSize, const size_t sectionNum, OUT size_t &sectionSize);
void free_remote_pe_section(BYTE *section_buffer);

/**
Reads PE file from the remote process into the supplied buffer. It expects the module base and size to be given.
*/
size_t read_remote_pe(const HANDLE processHandle, BYTE *moduleBase, const size_t moduleSize, OUT BYTE* buffer, const size_t bufferSize);

/**
Dumps PE file from the remote process into a file. It expects the module base and size to be given.
If 'unmap' is set to true, it automatically unmaps the file.
*/
bool dump_remote_pe(const char *outputFilePath, const HANDLE processHandle, BYTE *moduleBase, size_t moduleSize, bool unmap=true);
