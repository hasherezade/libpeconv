/**
* @file
* @brief   Functions and classes responsible for fixing Import Table. A definition of ImportedDllCoverage class.
*/

#pragma once

#include <windows.h>

#include <string>

#include <set>
#include <map>

#include <iterator>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"
#include "exports_mapper.h"

#define MIN_DLL_LEN 5

namespace peconv {

    /**
    a helper class that allows to store information about functions that could not be covered by the given mapping
    */
    class ImpsNotCovered
    {
    public:
        ImpsNotCovered() {}
        ~ImpsNotCovered() {}
        
        /*
        Number of stored records
        */
        size_t count() { return thunkToAddr.size();  }

        void insert(ULONGLONG thunk, ULONGLONG searchedAddr);

        std::map<ULONGLONG, ULONGLONG> thunkToAddr; //addresses of not recovered functions with their thunks (call_via)
    };

    /**
    fix imports in the given module, using the given map of all available exports
    */
    bool fix_imports(IN OUT PVOID modulePtr, IN size_t moduleSize, IN const peconv::ExportsMapper& exportsMap, OUT OPTIONAL peconv::ImpsNotCovered* notCovered);
    
    /**
    a helper class that allows to find out where the functions are imported from
    */
    class ImportedDllCoverage
    {
    public:
        /**
        A constructor of an object of ImportedDllCoverage class.
        \param _addresses : the list of filled imports (VAs): the addresses to be covered
        \param _exportsMap : the map of the exports of all the loaded DLLs (the space in which we will be searching)
        */
        ImportedDllCoverage(std::set<ULONGLONG>& _addresses, const peconv::ExportsMapper& _exportsMap)
            : addresses(_addresses), exportsMap(_exportsMap)
        {
        }

        /**
        Checks if all the addresses can be covered by one DLL. If yes, this dll will be saved into: dllName.
        \return true if the covering DLL for the addresses was found. false otherwise.
        */
        bool findCoveringDll();

        /** 
        Maps the addresses from the set to functions from the given DLL. 
        Results are saved into: addrToFunc.
        Addresses that could not be covered by the given DLL are saved into notFound.
        Before each execution, the content of involved variables is erased.
        \param _mappedDllName : the name of the DLL that we will be used to mapping. This DLL is saved into mappedDllName. 
        \return a number of covered functions
        */
        size_t mapAddressesToFunctions(const std::string &_mappedDllName);

       /**
       Check if the functions mapping is complete.
       \return the status: true if all the addresses are mapped to specific exports, false if not
       */
        bool isMappingComplete() { return (addresses.size() == addrToFunc.size()) ? true : false; }

        /**
        A mapping associating each of the covered function addresses with the set of exports (from mapped DLL) that cover this address
        */
        std::map<ULONGLONG, std::set<ExportedFunc>> addrToFunc;

        /**
        Addresses of the functions not found in the mapped DLL
        */
        std::set<ULONGLONG> notFound;

        /**
        Name of the covering DLL
        */
        std::string dllName;

    protected:
        /**
        A name of the  DLL that was used for mapping. In a typical scenario it will be the same as covering DLL, but may be set different.
        */
        std::string mappedDllName;

        /**
        A supplied set of the addresses of imported functions.
        Those addressed will be covered (associated with the corresponding exports from available DLLs, defined by exportsMap).
        */
        std::set<ULONGLONG> &addresses;

        /**
        A supplied exportsMap. Only used as a lookup, no changes applied.
        */
        const peconv::ExportsMapper& exportsMap;
    };
}
