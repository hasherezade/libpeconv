#pragma once

#include <Windows.h>

#include <string>

#include <set>
#include <map>

#include <iterator>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"
#include "exports_mapper.h"

#define MIN_DLL_LEN 5

namespace peconv {

    //fix imports in the given module, using the given map of all available exports
    bool fix_imports(PVOID modulePtr, size_t moduleSize, peconv::ExportsMapper& exportsMap);
    
    // a helper class that allows to find out where the functions are imported from
    class ImportedDllCoverage
    {
    public:
        //_addresses: the list of filled imports (VAs)
        //_exportsMap: the map of the exports of all loaded DLLs (the space in which we will be searching)
        ImportedDllCoverage(std::set<ULONGLONG>& _addresses, peconv::ExportsMapper& _exportsMap)
            : addresses(_addresses), exportsMap(_exportsMap)
        {
        }

        // Checks if all the addresses can be covered by one DLL. If yes, this dll will be saved into: dllName.
        bool findCoveringDll();

        // Maps the addresses from the set to functions from the given DLL. 
        // The used DLL name is saved into mappedDllName. Results are saved into: addrToFunc. 
        // Addresses that could not be covered by the given DLL are saved into notFound.
        // Before each execution, the content of involved variables is erased.
        // Returns a number of covered functions.
        size_t mapAddressesToFunctions(std::string dll);

       // //returns the status: true if all the addresses are mapped to functions' names, false if not
        bool isMappingComplete() { return (addresses.size() == addrToFunc.size()) ? true : false; }

        std::map<ULONGLONG, std::set<ExportedFunc>> addrToFunc;
        std::set<ULONGLONG> notFound; //addresses not found in the mappedDll

        std::string dllName; //covering DLL

    protected:
        // a name of the  DLL that was used for mapping. In a normal scenario it will be the same as coveringDLL, but may be set different.
        std::string mappedDllName;

        std::set<ULONGLONG> &addresses;
        peconv::ExportsMapper& exportsMap;
        
    };
}
