#include "peconv/imports_uneraser.h"

#include "peconv/logger.h"

using namespace peconv;

namespace {
    LPVOID search_name(std::string name, const char* modulePtr, size_t moduleSize)
    {
        const char* namec = name.c_str();
        const size_t searched_len = name.length() + 1; // with terminating NULL
        const char* found_ptr = std::search(modulePtr, modulePtr + moduleSize, namec, namec + searched_len);
        const size_t o = found_ptr - modulePtr;
        if (o < moduleSize) {
            return (LPVOID)(found_ptr);
        }
        return nullptr;
    }
};

bool ImportsUneraser::writeFoundDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, const std::string &found_name)
{
    LOG_DEBUG("Found name: %s.", found_name.c_str());
    LPSTR name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
    size_t full_name_len = found_name.length() + 1; // with terminating zero
    if (!validate_ptr(modulePtr, moduleSize, name_ptr, full_name_len)) {
        //corner case: allow to save the name at the very end of the buffer, without the terminating zero
        full_name_len--;
        if (!validate_ptr(modulePtr, moduleSize, name_ptr, full_name_len)) {
            return false; //invalid pointer, cannot save
        }
    }
    ::memcpy(name_ptr, found_name.c_str(), full_name_len);
    return true;
}

bool ImportsUneraser::uneraseDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, const std::string &dll_name)
{
    LPSTR name_ptr = nullptr;
    if (lib_desc->Name != 0) {
        name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
    }
    const size_t dll_len = dll_name.length();
    if (!name_ptr || !validate_ptr(modulePtr, moduleSize, name_ptr, dll_len)) {
        //try to get the cave:
        const DWORD cave_size = DWORD(dll_len + 1 + 5); //ending null + padding
        const PBYTE ptr = find_ending_cave(modulePtr, moduleSize, cave_size);
        if (!ptr) {
            LOG_ERROR("Cannot save the DLL name: %s.", dll_name.c_str());
            return false;
        }
        const DWORD cave_rva = static_cast<DWORD>(ptr - modulePtr);
        lib_desc->Name = cave_rva;
    }

    if (writeFoundDllName(lib_desc, dll_name)) {
        return true; // written the found name
    }
    return false;
}

template <typename FIELD_T>
bool ImportsUneraser::findNameInBinaryAndFill(IMAGE_IMPORT_DESCRIPTOR* lib_desc,
    LPVOID call_via_ptr,
    LPVOID thunk_ptr,
    const FIELD_T ordinal_flag,
    std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func
)
{
    if (!call_via_ptr || !modulePtr || !lib_desc) {
        return false; //malformed input
    }
    IMAGE_DATA_DIRECTORY *importsDir = get_directory_entry((BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importsDir) return false;

    const DWORD impAddr = importsDir->VirtualAddress; //start of the import table

    FIELD_T *call_via_val = (FIELD_T*)call_via_ptr;
    if (*call_via_val == 0) {
        //nothing to fill, probably the last record
        return false;
    }
    const ULONGLONG searchedAddr = ULONGLONG(*call_via_val);

    auto found = addr_to_func.find(searchedAddr);
    if (found == addr_to_func.end()) {
        LOG_WARNING("No mapped export mapped to the given address: 0x%llx.", (unsigned long long)searchedAddr);
        return false;
    }
    auto exportsWithAddr = found->second;
    bool is_name_saved = false;
    FIELD_T lastOrdinal = 0; //store also ordinal of the matching function

    std::set<ExportedFunc>::iterator funcname_itr;
    for (funcname_itr = exportsWithAddr.begin();
        funcname_itr != exportsWithAddr.end();
        ++funcname_itr)
    {
            const ExportedFunc& found_func = *funcname_itr;
            lastOrdinal = found_func.funcOrdinal;

            const char* names_start = ((const char*)modulePtr + impAddr);
            const size_t remaining_size = moduleSize - (names_start - (const char*)modulePtr);
            BYTE* found_ptr = (BYTE*)search_name(found_func.funcName, names_start, remaining_size);
            if (!found_ptr) {
                //name not found in the binary
                //TODO: maybe it is imported by ordinal?
                continue;
            }
            if (funcname_itr != exportsWithAddr.begin()) {
                LOG_DEBUG(">[*][0x%llx] %s.", (unsigned long long)searchedAddr, found_func.toString().c_str());
            }
            const ULONGLONG name_offset = (ULONGLONG)found_ptr - (ULONGLONG)modulePtr;
            LOG_DEBUG("Found the name at: 0x%llx.", (unsigned long long) name_offset);
            if (name_offset < sizeof(WORD)) {
                continue;
            }
            const ULONGLONG imp_rva = name_offset - sizeof(WORD); // subtract the size of Hint
            const PIMAGE_IMPORT_BY_NAME imp_field = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imp_rva);
            ::memcpy(thunk_ptr, &imp_field, sizeof(FIELD_T));
            LOG_DEBUG("Wrote found to offset: %p.", call_via_ptr);
            is_name_saved = true;
            break;
    }
    // name not found or could not be saved - fill the ordinal instead:
    if (!is_name_saved && lastOrdinal != 0) {
        LOG_DEBUG("Filling ordinal: 0x%llx.", (unsigned long long)lastOrdinal);
        FIELD_T ord_thunk = lastOrdinal | ordinal_flag;
        ::memcpy(thunk_ptr, &ord_thunk, sizeof(FIELD_T)); 
        is_name_saved = true;
    }
    return is_name_saved;
}

template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
bool ImportsUneraser::writeFoundFunction(IMAGE_THUNK_DATA_T* desc, const FIELD_T ordinal_flag, const ExportedFunc &foundFunc)
{
    if (foundFunc.isByOrdinal) {
        FIELD_T ordinal = foundFunc.funcOrdinal | ordinal_flag;
        FIELD_T* by_ord = (FIELD_T*) desc;
        (*by_ord) = ordinal;
        LOG_DEBUG("Saved ordinal: %ld", (unsigned long) ordinal);
        return true;
    }
    PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
    LPSTR func_name_ptr = reinterpret_cast<LPSTR>(by_name->Name);
    std::string found_name = foundFunc.funcName;
    // try to save the found name under the pointer:
    const size_t full_name_len = found_name.length() + 1; // with the ending '\0'
    if (!validate_ptr(modulePtr, moduleSize, func_name_ptr, full_name_len)) {
        LOG_ERROR("Cannot save the name: not enough space.");
        return false;
    }
    by_name->Hint = MASK_TO_WORD(foundFunc.funcOrdinal);
    ::memcpy(func_name_ptr, found_name.c_str(), full_name_len);
    LOG_DEBUG("Saved name: %s", found_name.c_str());
    return true;
}

template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
bool ImportsUneraser::fillImportNames(
    IN OUT IMAGE_IMPORT_DESCRIPTOR* lib_desc,
    IN const FIELD_T ordinal_flag,
    IN std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func,
    OUT OPTIONAL ImpsNotCovered* notCovered
)
{
    if (!lib_desc) return false;

    FIELD_T call_via = lib_desc->FirstThunk;
    if (!call_via) return false;

    size_t processed_imps = 0;
    size_t recovered_imps = 0;

    FIELD_T thunk_addr = lib_desc->OriginalFirstThunk;
    if (!thunk_addr) {
        thunk_addr = call_via;
    }

    BYTE* call_via_ptr = (BYTE*)((ULONGLONG)modulePtr + call_via);
    BYTE* thunk_ptr = (BYTE*)((ULONGLONG)modulePtr + thunk_addr);
    for (;
        validate_ptr(modulePtr, moduleSize, call_via_ptr, sizeof(FIELD_T)) && validate_ptr(modulePtr, moduleSize, thunk_ptr, sizeof(FIELD_T));
        call_via_ptr += sizeof(FIELD_T), thunk_ptr += sizeof(FIELD_T)
        )
    {
        FIELD_T *thunk_val = (FIELD_T*)thunk_ptr;
        FIELD_T *call_via_val = (FIELD_T*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            break;
        }
        IMAGE_THUNK_DATA_T* desc = (IMAGE_THUNK_DATA_T*)thunk_ptr;
        if (!validate_ptr(modulePtr, moduleSize, desc, sizeof(IMAGE_THUNK_DATA_T))) {
            LOG_WARNING("Invalid descriptor pointer: [0x%llx].", (unsigned long long)desc);
            break;
        }
        if (!desc->u1.Function) {
            break;
        }
        ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
        std::map<ULONGLONG,std::set<ExportedFunc>>::const_iterator found_itr = addr_to_func.find(searchedAddr);
        if (found_itr == addr_to_func.end() || found_itr->second.size() == 0) {
            //not found, move on
            if (notCovered) {
                const DWORD thunkRVA = MASK_TO_DWORD((ULONG_PTR)call_via_ptr - (ULONG_PTR)modulePtr);
                notCovered->insert(thunkRVA, searchedAddr);
            }
            continue;
        }
        std::set<ExportedFunc>::const_iterator funcname_itr = found_itr->second.begin();
        const peconv::ExportedFunc &foundFunc = *funcname_itr;

        LOG_DEBUG("[*][0x%llx] %s.", (unsigned long long)searchedAddr, funcname_itr->toString().c_str());
        bool is_name_saved = writeFoundFunction<FIELD_T, IMAGE_THUNK_DATA_T>(desc, ordinal_flag, *funcname_itr);
        if (!is_name_saved) {
            is_name_saved = findNameInBinaryAndFill<FIELD_T>(lib_desc, call_via_ptr, thunk_ptr, ordinal_flag, addr_to_func);
        }
        processed_imps++;
        if (is_name_saved) recovered_imps++;
    }

    return (recovered_imps == processed_imps);
}

bool ImportsUneraser::uneraseDllImports(IN OUT IMAGE_IMPORT_DESCRIPTOR* lib_desc, IN ImportedDllCoverage &dllCoverage, OUT OPTIONAL ImpsNotCovered* notCovered)
{
    //everything mapped, now recover it:
    bool is_filled = false;
    if (!is64) {
        is_filled = fillImportNames<DWORD, IMAGE_THUNK_DATA32>(lib_desc, IMAGE_ORDINAL_FLAG32, dllCoverage.addrToFunc, notCovered);
    } else {
        is_filled = fillImportNames<ULONGLONG, IMAGE_THUNK_DATA64>(lib_desc, IMAGE_ORDINAL_FLAG64, dllCoverage.addrToFunc, notCovered);
    }
    if (!is_filled) {
        LOG_ERROR("Could not fill some import names.");
        return false;
    }
    return is_filled;
}
