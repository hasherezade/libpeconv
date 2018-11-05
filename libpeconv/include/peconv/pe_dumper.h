#pragma once

#include <Windows.h>
#include "exports_mapper.h"

namespace peconv {

    typedef enum {
        PE_DUMP_AUTO = 0,// autodetect which dump mode is the most suitable for the given input
        PE_DUMP_VIRTUAL, // dump as it is in the memory (virtual)
        PE_DUMP_UNMAP, // convert to the raw format: using raw sections' headers
        PE_DUMP_REALIGN, //convert to the raw format: by realigning raw sections' headers to be the same as virtual (useful if the PE was unpacked in memory)
        PE_DUMP_MODES_COUNT
    } t_pe_dump_mode;

    /*
    Detect dump mode that is the most suitable for the given input.
    */
    t_pe_dump_mode detect_dump_mode(IN const BYTE* buffer, IN size_t mod_size);

    /**
    Dumps PE from the fiven buffer into a file. It expects the module base and size to be given. WARNING: the buffer may be preprocessed before dumping.
    dump_mode: specifies in which format the PE should be dumped. If the mode was set to PE_DUMP_AUTO, it autodetects mode and returns the detected one.
    exportsMap: optional. If exportsMap is supplied, it will try to recover destroyed import table of the PE, basing on the supplied map of exported functions.
    */
    bool dump_pe(IN const char *outputFilePath,
        IN OUT BYTE* buffer, IN size_t mod_size,
        IN const ULONGLONG moduleBase,
        IN OUT t_pe_dump_mode &dump_mode,
        IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr
    );

};// namespace peconv
