#include "peconv/pe_dumper.h"

#include "peconv/pe_hdrs_helper.h"
#include "peconv/pe_virtual_to_raw.h"
#include "peconv/fix_imports.h"
#include "peconv/file_util.h"
#include "peconv/pe_mode_detector.h"

#include <iostream>

using namespace peconv;

t_pe_dump_mode peconv::detect_dump_mode(const BYTE * buffer, size_t mod_size)
{
    t_pe_dump_mode dump_mode = peconv::PE_DUMP_UNMAP;
    if (peconv::is_pe_raw(buffer, mod_size)) {
        std::cout << "Mode set: Virtual (no unmap)" << std::endl;
        return peconv::PE_DUMP_VIRTUAL;
    }
    if (peconv::is_pe_expanded(buffer, mod_size)) {
        std::cout << "Mode set: Realign" << std::endl;
        return peconv::PE_DUMP_REALIGN;
    }
    std::cout << "Mode set: Unmap" << std::endl;
    return peconv::PE_DUMP_UNMAP;
}

bool peconv::dump_pe(const char *out_path,
    BYTE *buffer, size_t mod_size,
    const ULONGLONG start_addr,
    t_pe_dump_mode dump_mode,
    peconv::ExportsMapper* exportsMap
)
{
    // if the exportsMap is supplied, attempt to recover the (destroyed) import table:
    if (exportsMap != nullptr) {
        if (!peconv::fix_imports(buffer, mod_size, *exportsMap)) {
            std::cerr << "Unable to fix imports!" << std::endl;
        }
    }
    if (dump_mode == PE_DUMP_AUTO) {
        dump_mode = detect_dump_mode(buffer, mod_size);
    }

    BYTE* dump_data = buffer;
    size_t dump_size = mod_size;
    size_t out_size = 0;
    BYTE* unmapped_module = nullptr;

    if (dump_mode == peconv::PE_DUMP_UNMAP || dump_mode == peconv::PE_DUMP_REALIGN) {
        //if the image base in headers is invalid, set the current base and prevent from relocating PE:
        if (peconv::get_image_base(buffer) == 0) {
            peconv::update_image_base(buffer, (ULONGLONG)start_addr);
        }
        if (dump_mode == peconv::PE_DUMP_UNMAP) {
            unmapped_module = pe_virtual_to_raw(buffer, mod_size, (ULONGLONG)start_addr, out_size, false);
        }
        else if (dump_mode == peconv::PE_DUMP_REALIGN) {
            unmapped_module = peconv::pe_realign_raw_to_virtual(buffer, mod_size, (ULONGLONG)start_addr, out_size);
        }
        // unmap the PE file (convert from the Virtual Format into Raw Format)
        if (unmapped_module) {
            dump_data = unmapped_module;
            dump_size = out_size;
        }
    }
    // save the read module into a file
    bool is_dumped = dump_to_file(out_path, dump_data, dump_size);

    peconv::free_pe_buffer(unmapped_module, mod_size);
    return is_dumped;
}
