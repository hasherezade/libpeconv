#include "peconv/fix_imports.h"

#include <iostream>
#include <algorithm>

#include "peconv/imports_uneraser.h"


using namespace peconv;

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
