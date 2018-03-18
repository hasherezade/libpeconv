#include "peconv/fix_imports.h"

#include <iostream>
#include <algorithm>

#define MIN_DLL_LEN 5

using namespace peconv;

LPVOID search_name(std::string name, const char* modulePtr, size_t moduleSize)
{
    const char* namec = name.c_str();
    const size_t searched_len =  name.length() + 1; // with terminating NULL
    const char* found_ptr = std::search(modulePtr, modulePtr + moduleSize, namec, namec + searched_len);
    if (found_ptr == NULL) {
        return NULL;
    }
    size_t o = found_ptr - modulePtr;
    if (o < moduleSize) {
       return (LPVOID)(found_ptr);
    }
    return NULL;
}

template <typename FIELD_T>
bool findNameInBinaryAndFill(LPVOID modulePtr, size_t moduleSize,
                      IMAGE_IMPORT_DESCRIPTOR* lib_desc,
                      LPVOID call_via_ptr,
                      const FIELD_T ordinal_flag,
                      std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func
                      )
{
    if (call_via_ptr == NULL || modulePtr == NULL || lib_desc == NULL) {
        return false; //malformed input
    }
    FIELD_T *call_via_val = (FIELD_T*)call_via_ptr;
    if (*call_via_val == 0) {
        //nothing to fill, probably the last record
        return false;
    }
    ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
    bool is_name_saved = false;

    FIELD_T lastOrdinal = 0; //store also ordinal of the matching function
    std::set<ExportedFunc>::iterator funcname_itr = addr_to_func[searchedAddr].begin();

    for (funcname_itr = addr_to_func[searchedAddr].begin(); 
        funcname_itr != addr_to_func[searchedAddr].end(); 
        funcname_itr++) 
    {
        const ExportedFunc &found_func = *funcname_itr;
        lastOrdinal = found_func.funcOrdinal;

        const char* names_start = ((const char*) modulePtr + lib_desc->Name);
        BYTE* found_ptr = (BYTE*) search_name(found_func.funcName, names_start, moduleSize - (names_start - (const char*)modulePtr));
        if (!found_ptr) {
            //name not found in the binary
            //TODO: maybe it is imported by ordinal?
            continue;
        }
        
        const ULONGLONG name_offset = (ULONGLONG)found_ptr - (ULONGLONG)modulePtr;
#ifdef _DEBUG
        //if it is not the first name from the list, inform about it:
        if (funcname_itr != addr_to_func[searchedAddr].begin()) {
            std::cout << ">[*][" << std::hex << searchedAddr << "] " << found_func.toString() << std::endl;
        }
        std::cout <<"[+] Found the name at: " << std::hex << name_offset << std::endl;
#endif
        PIMAGE_IMPORT_BY_NAME imp_field = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(name_offset - sizeof(WORD)); // substract the size of Hint
        //TODO: validate more...
        memcpy(call_via_ptr, &imp_field, sizeof(FIELD_T));
#ifdef _DEBUG
        std::cout << "[+] Wrote found to offset: " << std::hex << call_via_ptr << std::endl;
#endif
        is_name_saved = true;
        break;
    }
    //name not found or could not be saved - filling the ordinal instead:
    if (is_name_saved == false) {
        if (lastOrdinal != 0) {
            std::cout << "[+] Filling ordinal: " << lastOrdinal << std::endl;
            FIELD_T ord_thunk = lastOrdinal | ordinal_flag;
            memcpy(call_via_ptr, &ord_thunk, sizeof(FIELD_T)); 
            is_name_saved = true;
        }
    }
    return is_name_saved;
}

template <typename FIELD_T, typename IMAGE_THUNK_DATA_T>
bool fillImportNames(IMAGE_IMPORT_DESCRIPTOR* lib_desc,
                     LPVOID modulePtr, size_t moduleSize, 
                     const FIELD_T ordinal_flag,
                     std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func)
{
    if (lib_desc == NULL) return false;

    FIELD_T call_via = lib_desc->FirstThunk;
    if (call_via == NULL) return false;

    size_t processed_imps = 0;
    size_t recovered_imps = 0;

    FIELD_T thunk_addr = lib_desc->OriginalFirstThunk;
    if (thunk_addr == NULL) {
        thunk_addr = call_via;
    }

    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        FIELD_T *thunk_val = (FIELD_T*)thunk_ptr;
        FIELD_T *call_via_val = (FIELD_T*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            break;
        }

        ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
        std::set<ExportedFunc>::iterator funcname_itr = addr_to_func[searchedAddr].begin();

        if (addr_to_func[searchedAddr].begin() == addr_to_func[searchedAddr].end()) {
            std::cerr << "[-] Function not recovered: [" << std::hex << searchedAddr << "] " << std::endl;
            call_via += sizeof(FIELD_T);
            thunk_addr += sizeof(FIELD_T);
            continue;
        }

#ifdef _DEBUG
        std::cout << "[*][" << std::hex << searchedAddr << "] " << funcname_itr->toString() << std::endl;
#endif
        bool is_name_saved = false;

        IMAGE_THUNK_DATA_T* desc = (IMAGE_THUNK_DATA_T*) thunk_ptr;
        if (desc->u1.Function == NULL) {
            break;
        }

        
        if (desc->u1.Ordinal & ordinal_flag) {
            // import by ordinal: already filled
            call_via += sizeof(FIELD_T);
            thunk_addr += sizeof(FIELD_T);
            continue;
        }

        if (funcname_itr->isByOrdinal) {
            std::cout << "This function is exported by ordinal: " << funcname_itr->toString() << std::endl;
            FIELD_T ordinal = funcname_itr->funcOrdinal | ordinal_flag;
            FIELD_T* by_ord = (FIELD_T*) &desc->u1.Ordinal;
            *by_ord = ordinal;
            is_name_saved = true;
#ifdef _DEBUG
            std::cout << "[+] Saved ordinal" << std::endl;
#endif
        }
        else {
            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
            LPSTR func_name_ptr = by_name->Name;
            std::string found_name = funcname_itr->funcName;
            bool is_nameptr_valid = validate_ptr(modulePtr, moduleSize, func_name_ptr, found_name.length());
            // try to save the found name under the pointer:
            if (is_nameptr_valid == true) {
                memcpy(func_name_ptr, found_name.c_str(), found_name.length() + 1); // with the ending '\0'
#ifdef _DEBUG
                std::cout << "[+] Saved name" << std::endl;
#endif
                is_name_saved = true;
            } else {
                // try to find the offset to the name in the module:
                is_name_saved = findNameInBinaryAndFill<FIELD_T>(modulePtr, moduleSize, lib_desc, call_via_ptr, ordinal_flag, addr_to_func);
            }
        }
        call_via += sizeof(FIELD_T);
        thunk_addr += sizeof(FIELD_T);
        processed_imps++;
        if (is_name_saved) recovered_imps++;

    } while (true);

    return (recovered_imps == processed_imps);
}

template <typename FIELD_T>
size_t findAddressesToFill(FIELD_T call_via, FIELD_T thunk_addr, LPVOID modulePtr, OUT std::set<ULONGLONG> &addresses)
{
    size_t addrCounter = 0;
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        FIELD_T *thunk_val = reinterpret_cast<FIELD_T*>(thunk_ptr);
        FIELD_T *call_via_val = reinterpret_cast<FIELD_T*>(call_via_ptr);
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            break;
        }
        ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
        addresses.insert(searchedAddr);
        addrCounter++;
        //---
        call_via += sizeof(FIELD_T);
        thunk_addr += sizeof(FIELD_T);
    } while (true);

    return addrCounter;
}

//find the name of the DLL that can cover all the addresses of imported functions
std::string find_covering_dll(std::set<ULONGLONG> &addresses, peconv::ExportsMapper& exportsMap)
{
    std::set<std::string> dllNames;
    bool isFresh = true;

    std::set<ULONGLONG>::iterator addrItr;
    for (addrItr = addresses.begin(); addrItr != addresses.end(); addrItr++) {
        ULONGLONG searchedAddr = *addrItr;
        //---
        // Find all the DLLs exporting this particular function (can be forwarded etc)
        //1. Get all the functions from all accessible DLLs that correspond to this address:
        const std::set<ExportedFunc>* exports_for_va = exportsMap.find_exports_by_va(searchedAddr);
        if (exports_for_va == nullptr) {
            std::cerr << "Cannot find any DLL exporting: " << std::hex << searchedAddr << std::endl;
            return "";
        }
        //2. Iterate through their DLL names and add them to a set:
        std::set<std::string> currDllNames;
        for (std::set<ExportedFunc>::iterator strItr = exports_for_va->begin(); 
            strItr != exports_for_va->end(); 
            strItr++)
        {
            currDllNames.insert(strItr->libName);
        }
        //3. Which of those DLLs covers also previous functions from this series?
        if (isFresh) {
            //if no other function was processed before, set the current DLL set as the total set
            dllNames = currDllNames;
            isFresh = false;
            continue;
        }
        // find the intersection between the total set and the current set
        std::set<std::string> resultSet;
        std::set_intersection(dllNames.begin(), dllNames.end(),
            currDllNames.begin(), currDllNames.end(),
            std::inserter(resultSet, resultSet.begin())
        );
        //std::cout << "ResultSet size: " << resultSet.size() << std::endl;
        
        if (resultSet.size() == 0) {
#ifdef _DEBUG
            std::cerr << "Suspicious address: " << std::hex << searchedAddr << " not found in the currently processed DLL"  << std::endl;
            std::string prev_lib = *(dllNames.begin());
            std::cerr << "Not found in: " << prev_lib << std::endl;

            std::string curr_lib = *(currDllNames.begin());
            std::cerr << "Found in: " << curr_lib << std::endl;
#endif
            //reinitializate the set and keep going...
            dllNames = currDllNames;
            continue;
        }
        dllNames = resultSet;
        //---
    }
    if (dllNames.size() > 0) {
        return *(dllNames.begin());
    }
    return "";
}

bool ImportedDllCoverage::findCoveringDll()
{
    std::string found_name = find_covering_dll(this->addresses, this->exportsMap);
    if (found_name.length() == 0) {
        std::cerr << "Cannot find a covering DLL" << std::endl;
        return false;
    }
    this->dllName = found_name;
//#ifdef _DEBUG
    std::cout << "[+] Found DLL name: " << found_name << std::endl;
//#endif
    return true;
}

size_t map_addresses_to_functions(std::set<ULONGLONG> &addresses, 
                               std::string coveringDll,
                               peconv::ExportsMapper& exportsMap,
                               OUT std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func
                               )
{
    size_t coveredCount = 0;
    std::set<ULONGLONG>::iterator addrItr;
    for (addrItr = addresses.begin(); addrItr != addresses.end(); addrItr++) {

        ULONGLONG searchedAddr = *addrItr;

        const std::set<ExportedFunc>* exports_for_va = exportsMap.find_exports_by_va(searchedAddr);
        if (exports_for_va == nullptr) {
#ifdef _DEBUG
            std::cerr << "Cannot find any DLL exporting: " << std::hex << searchedAddr << std::endl;
#endif
            return 0;
        }

        std::set<std::string> currDllNames;

        for (std::set<ExportedFunc>::iterator strItr = exports_for_va->begin(); 
            strItr != exports_for_va->end(); 
            strItr++)
        {
            std::string dll_name = strItr->libName;
            if (dll_name != coveringDll) {
                continue;
            }
            ExportedFunc func = *strItr;
            addr_to_func[searchedAddr].insert(func);
            coveredCount++;
        }
        if (addr_to_func.find(searchedAddr) == addr_to_func.end()) {
            const ExportedFunc* func = exportsMap.find_export_by_va(searchedAddr);
            std::cerr << "[WARNING] A function: " << func->toString() << " not found in the covering DLL: " << coveringDll << std::endl;
        }
    }
    return coveredCount;
}

bool ImportedDllCoverage::mapAddressesToFunctions(std::string dll)
{
    size_t coveredCount = map_addresses_to_functions(this->addresses, dll, this->exportsMap, this->addrToFunc); 
    if (coveredCount < addresses.size()) {
        std::cerr << "[-] Not all addresses are covered! covered: " << coveredCount << " total: " << addresses.size() << std::endl;
        return false;
    }
#ifdef _DEBUG
    std::cout << "All covered!" << std::endl;
#endif
    return true;
}

bool ImportedDllCoverage::mapAddressesToFunctions()
{
    return mapAddressesToFunctions(this->dllName);
}

bool recoverErasedDllName(PVOID modulePtr, size_t moduleSize, 
                          IMAGE_IMPORT_DESCRIPTOR* lib_desc, 
                          std::string found_name
                          )
{
    if (found_name.find_last_of(".")  >= found_name.length()) {
        //if no extension found, append extension DLL
        found_name += ".dll"; //TODO: it not always has to have extension DLL!
    }
#ifdef _DEBUG
    std::cout << "Found name:" << found_name << std::endl;
#endif
    LPSTR name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);

    if (!validate_ptr(modulePtr, moduleSize, name_ptr, found_name.length())) {
        std::cerr << "[-] Invalid pointer to the name!\n";
        return false;
    }
    memcpy(name_ptr, found_name.c_str(), found_name.length() + 1); // with terminating zero
    return true;
}

bool ImportsUneraser::uneraseDllName(IMAGE_IMPORT_DESCRIPTOR* lib_desc, ImportedDllCoverage &dllCoverage)
{
    bool is_lib_erased = false;
    bool is_lib_name_corrupt = false;

    LPSTR name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
    if (!validate_ptr(modulePtr, moduleSize, name_ptr, sizeof(char) * MIN_DLL_LEN)) {
        std::cerr << "[-] Invalid pointer to the name!\n";
        is_lib_name_corrupt = true;
    }
    std::string lib_name = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
    if (lib_name.length() == 0) {
        is_lib_erased = true;
    }

    if (is_lib_erased) {
        if (recoverErasedDllName(modulePtr, moduleSize, lib_desc, dllCoverage.dllName)) {
            return true;
        }
        std::cerr << "Failed to recover the erased DLL name\n";
        return false;
    }
    if (is_lib_name_corrupt) {
        return false; //TODOD: cover this case
    }
    return true;
}

bool ImportsUneraser::uneraseDllImports(IMAGE_IMPORT_DESCRIPTOR* lib_desc, ImportedDllCoverage &dllCoverage)
{
    //everything mapped, now recover it:
    bool is_filled = false;
    if (!is64) {
        is_filled = fillImportNames<DWORD, IMAGE_THUNK_DATA32>(lib_desc, modulePtr, moduleSize, IMAGE_ORDINAL_FLAG32, dllCoverage.addrToFunc);
    } else {
        is_filled = fillImportNames<ULONGLONG, IMAGE_THUNK_DATA64>(lib_desc, modulePtr, moduleSize, IMAGE_ORDINAL_FLAG64, dllCoverage.addrToFunc);
    }
    if (!is_filled) {
        std::cerr << "[-] Could not fill some import names!" << std::endl;
        return false;
    }
    return is_filled;
}

bool peconv::fix_imports(PVOID modulePtr, size_t moduleSize, peconv::ExportsMapper& exportsMap)
{
    IMAGE_DATA_DIRECTORY *importsDir = peconv::get_directory_entry((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) {
        return true; // done! no imports -> nothing to fix
    }
    bool is64 = peconv::is64bit((BYTE*)modulePtr);
    DWORD maxSize = importsDir->Size;
    DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    DWORD parsedSize = 0;
#ifdef _DEBUG
    printf("---IMP---\n");
#endif

    ImportsUneraser impUneraser(modulePtr, moduleSize);

    while (parsedSize < maxSize) {

        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, lib_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            printf("[-] Invalid descriptor pointer!\n");
            return false;
        }
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }
        if (lib_desc->TimeDateStamp == (-1)) {
            std::cerr << "[!] This is a bound import. Bound imports are not supported\n";
            continue;
        }
#ifdef _DEBUG
        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
#endif
        LPSTR name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
        std::string lib_name = "";
        if (validate_ptr(modulePtr, moduleSize, name_ptr, sizeof(char) * MIN_DLL_LEN)) {
            lib_name = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
            //std::cerr << "[-] Invalid pointer to the name!\n";
            //return false;
        }

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk; // warning: it can be NULL!
        std::set<ULONGLONG> addresses;
        if (!is64) {
            findAddressesToFill<DWORD>(call_via, thunk_addr, modulePtr, addresses);
        } else {
            findAddressesToFill<ULONGLONG>(call_via, thunk_addr, modulePtr, addresses);
        }
        ImportedDllCoverage dllCoverage(addresses, exportsMap);
        if (!dllCoverage.findCoveringDll()) {
            return false;
        }

        bool is_lib_erased = false;

        lib_name = get_dll_name(lib_name);

        if (lib_name.length() == 0) {
            is_lib_erased = true;
            lib_name = dllCoverage.dllName;
        }

#ifdef _DEBUG
        std::cout << lib_name << std::endl;
#endif
        if (!dllCoverage.mapAddressesToFunctions(lib_name)) {
            // could not cover all the functions in this DLL
            continue;
        }

        //everything mapped, now recover it:
        if (!impUneraser.uneraseDllImports(lib_desc, dllCoverage)) {
            return false;
        }
        impUneraser.uneraseDllName(lib_desc, dllCoverage);
    }
#ifdef _DEBUG
    std::cout << "---------" << std::endl;
#endif
    return true;
}
