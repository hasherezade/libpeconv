#include <peconv/find_base.h>
#include <peconv/pe_hdrs_helper.h>
#include <peconv/relocate.h>
#include <set>
#include <map>
#include <iostream>

namespace peconv {

    class CollectCodeRelocs : public RelocBlockCallback
    {
    public:
        CollectCodeRelocs(BYTE *pe_buffer, size_t buffer_size, IN bool _is64bit, OUT std::set<ULONGLONG> &_relocs)
            : RelocBlockCallback(_is64bit), relocs(_relocs),
            peBuffer(pe_buffer), bufferSize(buffer_size)
        {
            codeSec = getCodeSection(peBuffer, bufferSize);
        }

        virtual bool processRelocField(ULONG_PTR relocField)
        {
            if (!codeSec) return false;

            ULONGLONG reloc_addr = (relocField - (ULONGLONG)peBuffer);
            const bool is_in_code = (reloc_addr >= codeSec->VirtualAddress) && (reloc_addr < codeSec->Misc.VirtualSize);
            if (!is64bit && !is_in_code) {
                // in case of 32 bit PEs process only the relocations form the code section
                return true;
            }
            ULONGLONG rva = 0;
            if (is64bit) {
                ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)relocField);
                rva = (*relocateAddr);
                //std::cout << std::hex << (relocField - (ULONGLONG)peBuffer) << " : " << rva << std::endl;
            }
            else {
                DWORD* relocateAddr = (DWORD*)((ULONG_PTR)relocField);
                rva = ULONGLONG(*relocateAddr);
                //std::cout << std::hex << (relocField - (ULONGLONG)peBuffer) << " : " << rva << std::endl;
            }
            relocs.insert(rva);
            return true;
        }

        static PIMAGE_SECTION_HEADER getCodeSection(BYTE *peBuffer, size_t bufferSize)
        {
            size_t sec_count = peconv::get_sections_count(peBuffer, bufferSize);
            for (size_t i = 0; i < sec_count; i++) {
                PIMAGE_SECTION_HEADER hdr = peconv::get_section_hdr(peBuffer, bufferSize, i);
                if (!hdr) break;
                if (hdr->VirtualAddress == 0 || hdr->SizeOfRawData == 0) {
                    continue;
                }
                if (hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    return hdr;
                }
            }
            return nullptr;
        }

    protected:
        std::set<ULONGLONG> &relocs;
        PIMAGE_SECTION_HEADER codeSec;

        BYTE *peBuffer;
        size_t bufferSize;
    };
}

ULONGLONG peconv::find_base_candidate(IN BYTE* modulePtr, IN size_t moduleSize)
{
    if (moduleSize == 0) {
        moduleSize = peconv::get_image_size((const BYTE*)modulePtr);
    }
    if (moduleSize == 0) return 0;

    bool is64 = peconv::is64bit(modulePtr);
    std::set<ULONGLONG> relocs;
    peconv::CollectCodeRelocs callback(modulePtr, moduleSize, is64, relocs);
    if (!peconv::process_relocation_table(modulePtr, moduleSize, &callback)) {
        return 0;
    }
    if (relocs.size() == 0) {
        return 0;
    }

    PIMAGE_SECTION_HEADER hdr = peconv::CollectCodeRelocs::getCodeSection(modulePtr, moduleSize);
    if (!hdr) {
        return 0;
    }
    const ULONGLONG mask = ~ULONGLONG(0xFFFF);
    std::map<ULONGLONG, size_t>base_candidates;

    std::set<ULONGLONG>::iterator itr = relocs.begin();
    
    for (itr = relocs.begin(); itr != relocs.end(); ++itr) {
        const ULONGLONG guessed_base = (*itr) & mask;
        std::map<ULONGLONG, size_t>::iterator found = base_candidates.find(guessed_base);
        if (found == base_candidates.end()) {
            base_candidates[guessed_base] = 0;
        }
        base_candidates[guessed_base]++;
    }
    ULONGLONG most_freqent = 0;
    size_t max_freq = 0;
    std::map<ULONGLONG, size_t>::iterator mapItr;
    for (mapItr = base_candidates.begin(); mapItr != base_candidates.end(); ++mapItr) {
        if (mapItr->second >= max_freq) {
            most_freqent = mapItr->first;
            max_freq = mapItr->second;
        }
    }
    for (itr = relocs.begin(); itr != relocs.end(); ++itr) {
        ULONGLONG first = *itr;
        ULONGLONG first_base = first & mask;
        if (first_base > most_freqent) {
            break;
        }
        ULONGLONG delta = most_freqent - first_base;
        if (delta < moduleSize) {
            return first_base;
        }
    }
    return 0;
}
