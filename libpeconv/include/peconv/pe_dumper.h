/**
* @file
* @brief   Dumping PE from the memory buffer into a file.
*/

#pragma once

#include <windows.h>
#include "exports_mapper.h"

namespace peconv {

    /**
    A mode in which the PE fille be dumped.
    */
    typedef enum {
        PE_DUMP_AUTO = 0, /**< autodetect which dump mode is the most suitable for the given input */
        PE_DUMP_VIRTUAL,/**< dump as it is in the memory (virtual) */
        PE_DUMP_UNMAP, /**< convert to the raw format: using raw sections' headers */
        PE_DUMP_REALIGN, /**< convert to the raw format: by realigning raw sections' headers to be the same as virtual (useful if the PE was unpacked in memory) */
        PE_DUMP_MODES_COUNT /**< total number of the dump modes */
    } t_pe_dump_mode;

    /**
    Detect dump mode that is the most suitable for the given input.
    \param buffer : the buffer containing the PE to be dumped.
    \param buffer_size : the size of the given buffer
    */
    t_pe_dump_mode detect_dump_mode(IN const BYTE* buffer, IN size_t buffer_size);

    /**
    Dumps PE from the fiven buffer into a file. It expects the module base and size to be given. 
    \param outputFilePath : name of the file where the dump should be saved
    \param buffer : the buffer containing the PE to be dumped. WARNING: the buffer may be preprocessed before dumping.
    \param buffer_size : the size of the given buffer
    \param module_base : the base to which the PE buffer was relocated
    \param dump_mode : specifies in which format the PE should be dumped. If the mode was set to PE_DUMP_AUTO, it autodetects mode and returns the detected one.
    \param exportsMap : optional. If exportsMap is supplied, it will try to recover destroyed import table of the PE, basing on the supplied map of exported functions.
    */
    bool dump_pe(
        IN LPCTSTR outputFilePath,
        IN OUT BYTE* buffer,
        IN size_t buffer_size,
        IN const ULONGLONG module_base,
        IN OUT t_pe_dump_mode &dump_mode,
        IN OPTIONAL const peconv::ExportsMapper* exportsMap = nullptr
    );

};// namespace peconv
