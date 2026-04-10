#include "peconv/fix_imports.h"
#include "peconv/imports_uneraser.h"
#include "peconv/file_util.h"

#include "peconv/logger.h"
#include "peconv/util.h"

#include <algorithm>

using namespace peconv;

template <typename FIELD_T>
size_t find_addresses_to_fill(FIELD_T call_via, FIELD_T thunk_addr, LPVOID modulePtr, size_t moduleSize, IN const peconv::ExportsMapper& exportsMap, OUT std::set<ULONGLONG> &addresses)
{
    if (!modulePtr || call_via == 0) return 0;

    size_t addrCounter = 0;
    do {
        if (thunk_addr) { // use it for validation, only if it is non-zero
            LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
            if (!validate_ptr(modulePtr, moduleSize, thunk_ptr, sizeof(FIELD_T))) {
                break;
            }
        }
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (!validate_ptr(modulePtr, moduleSize, call_via_ptr, sizeof(FIELD_T))) {
            break;
        }
        FIELD_T *call_via_val = reinterpret_cast<FIELD_T*>(call_via_ptr);
        if ((*call_via_val) == 0) {
            //nothing to fill, probably the last record
            break;
        }
        ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
        if (exportsMap.find_export_by_va(searchedAddr) != nullptr) {
            addresses.insert(searchedAddr);
            addrCounter++;
        }
        //---
        call_via += sizeof(FIELD_T);
        if (thunk_addr) { // increment only if the initial value was not 0
            thunk_addr += sizeof(FIELD_T);
        }
    } while (true);

    return addrCounter;
}

std::set<std::string> get_all_dlls_exporting_function(ULONGLONG func_addr, const peconv::ExportsMapper& exportsMap)
{
    std::set<std::string> currDllNames;
    //1. Get all the functions from all accessible DLLs that correspond to this address:
    const std::set<ExportedFunc>* exports_for_va = exportsMap.find_exports_by_va(func_addr);
    if (!exports_for_va) {
        LOG_WARNING("Cannot find any DLL exporting: 0x%llx.", (unsigned long long)func_addr);
        return currDllNames; //empty
    }
    //2. Iterate through their DLL names and add them to a set:
    for (std::set<ExportedFunc>::iterator strItr = exports_for_va->begin();
        strItr != exports_for_va->end();
        ++strItr)
    {
        currDllNames.insert(strItr->libName);
    }
    return currDllNames;
}

std::set<std::string> get_dlls_intersection(const std::set<std::string> &dllNames, const std::set<std::string> &currDllNames)
{
    std::set<std::string> resultSet;
    std::set_intersection(dllNames.begin(), dllNames.end(),
        currDllNames.begin(), currDllNames.end(),
        std::inserter(resultSet, resultSet.begin())
    );
    return resultSet;
}

//find the name of the DLL that can cover all the addresses of imported functions
std::string find_covering_dll(std::set<ULONGLONG> &addresses, const peconv::ExportsMapper& exportsMap)
{
    std::set<std::string> mainDllsSet;
    std::set<std::string> reserveDllSet;
    bool isFresh = true;

    // the earliest addresses are more significant for the final decision on what DLL to choose
    // so, they should be processed at the end
    std::set<ULONGLONG>::iterator addrItr;

    for (addrItr = addresses.begin(); addrItr != addresses.end(); ++addrItr) {
        ULONGLONG searchedAddr = *addrItr;
        //---
        // 1. Find all the DLLs exporting this particular function (can be forwarded etc)
        std::set<std::string> currDllNames = get_all_dlls_exporting_function(searchedAddr, exportsMap);

        //2. Which of those DLLs covers also previous functions from this series?
        if (isFresh) {
            //if no other function was processed before, set the current DLL set as the total set
            mainDllsSet = currDllNames;
            isFresh = false;
            continue;
        }
        // find the intersection between the total set and the current set
        std::set<std::string> resultSet = get_dlls_intersection(mainDllsSet, currDllNames);
        if (resultSet.size() > 0) {
            //found intersection, overwrite the main set
            mainDllsSet = resultSet;
            continue;
        }
        // if no intersection found in the main set, check if there is any in the reserved set:
        resultSet = get_dlls_intersection(reserveDllSet, currDllNames);
        if (resultSet.size() > 0) {
            //found intersection, overwrite the main set
            reserveDllSet = mainDllsSet; // move the current to the reserve
            mainDllsSet = resultSet;
            continue;
        }
        // no intersection found with any of the sets:
        reserveDllSet = currDllNames; //set is as a reserved DLL: to be used if it will reoccur
    }
    if (mainDllsSet.size() > 0) {
        const std::string main_dll = *(mainDllsSet.begin());
        return main_dll;
    }
    return "";
}

bool ImportedDllCoverage::findCoveringDll()
{
    std::string found_name = find_covering_dll(this->addresses, this->exportsMap);
    if (found_name.length() == 0) {
        LOG_WARNING("Cannot find a covering DLL.");
        return false;
    }
    this->dllName = found_name;
    LOG_DEBUG("Found DLL name: %s.", found_name.c_str());
    return true;
}

size_t map_addresses_to_functions(std::set<ULONGLONG> &addresses, 
    IN const std::string &chosenDll,
    IN const peconv::ExportsMapper& exportsMap,
    OUT std::map<ULONGLONG, std::set<ExportedFunc>> &addr_to_func,
    OUT std::set<ULONGLONG> &not_found
)
{
    std::set<ULONGLONG> coveredAddresses;
    std::set<ULONGLONG>::iterator addrItr;
    for (addrItr = addresses.begin(); addrItr != addresses.end(); ++addrItr) {

        ULONGLONG searchedAddr = *addrItr;

        const std::set<ExportedFunc>* exports_for_va = exportsMap.find_exports_by_va(searchedAddr);
        if (exports_for_va == nullptr) {
            not_found.insert(searchedAddr);
            LOG_WARNING("Cannot find any DLL exporting: 0x%llx.", (unsigned long long)searchedAddr);
            continue;
        }

        for (std::set<ExportedFunc>::iterator strItr = exports_for_va->begin(); 
            strItr != exports_for_va->end(); 
            ++strItr)
        {
            std::string dll_name = strItr->libName;
            if (dll_name != chosenDll) {
                continue;
            }
            ExportedFunc func = *strItr;
            addr_to_func[searchedAddr].insert(func);
            coveredAddresses.insert(searchedAddr);
        }
        if (addr_to_func.find(searchedAddr) == addr_to_func.end()) {
            const ExportedFunc* func = exportsMap.find_export_by_va(searchedAddr);
            not_found.insert(searchedAddr);
            if (func) {
                LOG_WARNING("Function '%s' not found in the covering DLL: %s.", func->toString().c_str(), chosenDll.c_str());
            }
            else {
                LOG_WARNING("Function at [0x%llx] not found in the covering DLL: %s.", (unsigned long long)searchedAddr, chosenDll.c_str());
            }
        }
    }
    return coveredAddresses.size();
}

size_t ImportedDllCoverage::mapAddressesToFunctions(const std::string &dll)
{
    //reset all stored info:
    this->mappedDllName = dll;
    if (this->addrToFunc.size() > 0) {
        this->addrToFunc.clear();
    }
    this->notFound.clear();

    const size_t coveredCount = map_addresses_to_functions(this->addresses, dll, this->exportsMap, this->addrToFunc, this->notFound);
    if (notFound.size()) {
        LOG_WARNING("Not all addresses are covered! Not found: %zu.", notFound.size());
    } else {
        LOG_DEBUG("All addresses covered.");
    }
    return coveredCount;
}

void ImpsNotCovered::insert(DWORD thunkRVA, ULONGLONG searchedAddr)
{
    LOG_WARNING("Function not recovered: [0x%llx].", (unsigned long long)searchedAddr);
    thunkToAddr[thunkRVA] = searchedAddr;
}


bool peconv::fix_imports(IN OUT PVOID modulePtr, IN size_t moduleSize, IN const peconv::ExportsMapper& exportsMap, OUT OPTIONAL peconv::ImpsNotCovered* notCovered)
{
    const bool skip_bound = false; // skip bound imports?
    IMAGE_DATA_DIRECTORY *importsDir = peconv::get_directory_entry((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importsDir) {
        return true; // done! no imports -> nothing to fix
    }
    bool is64 = peconv::is64bit((BYTE*)modulePtr);
    DWORD maxSize = importsDir->Size;
    DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = nullptr;
    DWORD parsedSize = 0;
    LOG_DEBUG("---IMP---");

    while (parsedSize < maxSize) {

        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, lib_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            LOG_ERROR("Invalid import descriptor pointer.");
            return false;
        }
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!lib_desc->OriginalFirstThunk && !lib_desc->FirstThunk) {
            break;
        }
        const bool is_bound = (lib_desc->TimeDateStamp == (-1));
        if (is_bound && skip_bound) {
            continue;
        }
        LOG_DEBUG("Imported Lib: %x : %x : %x", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
        
        std::string lib_name = "";
        if (lib_desc->Name != 0) {
            LPSTR name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
            if (is_valid_string(modulePtr, moduleSize, name_ptr)) {
                lib_name = name_ptr;
            }
        }

        const DWORD call_via = lib_desc->FirstThunk;
        const DWORD thunk_addr = lib_desc->OriginalFirstThunk; // warning: it can be NULL!
        std::set<ULONGLONG> addresses;
        if (!is64) {
            find_addresses_to_fill<DWORD>(call_via, thunk_addr, modulePtr, moduleSize, exportsMap, addresses);
        } else {
            find_addresses_to_fill<ULONGLONG>(call_via, thunk_addr, modulePtr, moduleSize, exportsMap, addresses);
        }
        ImportedDllCoverage dllCoverage(addresses, exportsMap);
        bool is_all_covered = dllCoverage.findCoveringDll();
        bool is_lib_erased = false;

        lib_name = get_dll_shortname(lib_name); //without extension

        if (lib_name.length() == 0) {
            is_lib_erased = true;
            if (is_all_covered) {
                // set a name of the covering DLL:
                lib_name = dllCoverage.dllName;
            }
        }
        if (lib_name.length() == 0) {
            //could not find a relevant DLL
            continue;
        }
        LOG_DEBUG("Lib: %s.", lib_name.c_str());
        if (!dllCoverage.mapAddressesToFunctions(lib_name)) {
            // cannot find any functions imported from this DLL
            continue;
        }
        //everything mapped, now recover it:
        ImportsUneraser impUneraser(modulePtr, moduleSize);
        if (!impUneraser.uneraseDllImports(lib_desc, dllCoverage, notCovered)) {
            return false;
        }
        if (is_lib_erased) {
            const std::string dll_with_ext = exportsMap.get_dll_fullname(dllCoverage.dllName);
            impUneraser.uneraseDllName(lib_desc, dll_with_ext);
        }
    }
    LOG_DEBUG("---------");
    return true;
}
