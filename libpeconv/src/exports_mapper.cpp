#include "peconv/exports_mapper.h"
#include <algorithm>
#include <iostream>


using namespace peconv;

void ExportsMapper::print_va_to_func(std::stringstream &stream) const
{
    std::map<ULONGLONG, std::set<ExportedFunc>>::const_iterator itr;

    for (itr = va_to_func.begin(); itr != va_to_func.end(); ++itr) {
        
        stream << std::hex << itr->first << " :\n";

        std::set<ExportedFunc>::const_iterator itr2;
        const std::set<ExportedFunc> &funcs = itr->second;

        for (itr2 = funcs.begin(); itr2 != funcs.end(); ++itr2) {
            stream << "\t" << itr2->toString() << "\n";
        }
    }
}

void ExportsMapper::print_func_to_va(std::stringstream &stream) const
{
    std::map<ExportedFunc, ULONGLONG>::const_iterator itr;
    for (itr = func_to_va.begin(); itr != func_to_va.end(); ++itr) {
        stream << itr->first.toString() << " : "
            << std::hex << itr->second << "\n";
    }
}

ULONGLONG rebase_va(ULONGLONG va, ULONGLONG currBase, ULONGLONG targetBase)
{
    if (currBase == targetBase) {
        return va;
    }
    ULONGLONG rva =  va - (ULONGLONG) currBase;
    return rva + targetBase;
}

size_t ExportsMapper::make_ord_lookup_tables(
    PVOID modulePtr, 
    size_t moduleSize,
    std::map<PDWORD, DWORD> &va_to_ord
    )
{
    IMAGE_EXPORT_DIRECTORY* exp = peconv::get_export_directory((HMODULE) modulePtr);
    if (exp == NULL) return 0;

    SIZE_T functCount = exp->NumberOfFunctions;
    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD ordBase = exp->Base;

    //go through names:
    for (DWORD i = 0; i < functCount; i++) {
        DWORD* recordRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        if (*recordRVA == 0) {
#ifdef _DEBUG
            std::cout << ">>> Skipping 0 function address at RVA:" << std::hex << (BYTE*)recordRVA - (BYTE*)modulePtr<< "(ord)\n";
#endif
            //skip if the function RVA is 0 (empty export)
            continue;
        }
        if (!peconv::validate_ptr(modulePtr, moduleSize, recordRVA, sizeof(DWORD))) {
            break;
        }
        DWORD ordinal = ordBase + i;
        va_to_ord[recordRVA] = ordinal;
    }
    return functCount;
}

size_t ExportsMapper::resolve_forwarders(const ULONGLONG va, ExportedFunc &currFunc)
{
    size_t resolved = 0;
    //resolve forwarders of this function (if any):
    std::map<ExportedFunc, std::set<ExportedFunc>>::iterator fItr = forwarders_lookup.find(currFunc);
    if (fItr != forwarders_lookup.end()) {
        //printf("[+] Forwarders (%d):\n", fItr->second.size());
        std::set<ExportedFunc>::iterator sItr;
        for (sItr = fItr->second.begin(); sItr != fItr->second.end(); ++sItr) {
            //printf("-> %s\n", sItr->c_str());
            associateVaAndFunc(va, *sItr);
            resolved++;
        }
    }
    return resolved;
}

bool ExportsMapper::add_forwarded(ExportedFunc &currFunc, DWORD callRVA, PBYTE modulePtr, size_t moduleSize)
{
    PBYTE fPtr = modulePtr + callRVA;
    if (!peconv::validate_ptr(modulePtr, moduleSize, fPtr, 1)) {
        return false;
    }
    if (peconv::forwarder_name_len(fPtr) < 1) {
        return false; //not forwarded
    }
    std::string forwardedFunc = format_dll_func((char*)fPtr);
    if (forwardedFunc.length() == 0) {
        return false; //not forwarded
    }

    ExportedFunc forwarder(forwardedFunc);
    if (!forwarder.isValid()) {
#ifdef _DEBUG
        std::cerr << "Skipped invalid forwarder" << std::endl;
#endif
        return false;
    }
    forwarders_lookup[forwarder].insert(currFunc);

    if (func_to_va[forwarder] != 0) {
        ULONGLONG va = func_to_va[forwarder];
        associateVaAndFunc(va, currFunc);
    }
    return true;
}

DWORD get_ordinal(PDWORD recordPtr, std::map<PDWORD, DWORD> &va_to_ord)
{
    std::map<PDWORD, DWORD>::iterator ord_itr = va_to_ord.find(recordPtr);
    if (ord_itr == va_to_ord.end()) {
        //ordinal not found
        return -1;
    }
    DWORD ordinal = ord_itr->second;
    va_to_ord.erase(ord_itr);
    return ordinal;
}

bool ExportsMapper::add_to_maps(ULONGLONG va, ExportedFunc &currFunc)
{
    associateVaAndFunc(va, currFunc);
    resolve_forwarders(va, currFunc);
    return true;
}

bool is_valid_export_table(IMAGE_EXPORT_DIRECTORY* exp, HMODULE modulePtr, const size_t module_size)
{
    if (exp == nullptr) return false;

    const SIZE_T namesCount = exp->NumberOfNames;
    const SIZE_T funcCount = exp->NumberOfFunctions;

    const DWORD funcsListRVA = exp->AddressOfFunctions;
    const DWORD funcNamesListRVA = exp->AddressOfNames;
    const DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    for (DWORD i = 0; i < funcCount; i++) {
        DWORD* recordRVA = (DWORD*)(funcsListRVA + (BYTE*)modulePtr + i * sizeof(DWORD));
        if (*recordRVA == 0) {
            //skip if the function RVA is 0 (empty export)
            continue;
        }
        if (!peconv::validate_ptr(modulePtr, module_size, recordRVA, sizeof(DWORD))) {
            return false;
        }
    }

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)modulePtr + i * sizeof(WORD));
        if ((!peconv::validate_ptr(modulePtr, module_size, nameRVA, sizeof(DWORD)))
            || (!peconv::validate_ptr(modulePtr, module_size, nameIndex, sizeof(WORD))))
        {
            return false;
        }
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)modulePtr + (*nameIndex) * sizeof(DWORD));
        if (!peconv::validate_ptr(modulePtr, module_size, funcRVA, sizeof(DWORD)))
        {
            return false;
        }
    }
    return true;
}

ExportsMapper::ADD_FUNC_RES ExportsMapper::add_function_to_lookup(HMODULE modulePtr, ULONGLONG moduleBase, size_t moduleSize, ExportedFunc &currFunc, DWORD callRVA)
{
    if (add_forwarded(currFunc, callRVA, (BYTE*)modulePtr, moduleSize)) {
#ifdef _DEBUG
        char* fPtr = (char*)modulePtr + callRVA;
        std::cout << "FWD " << currFunc.toString() << " -> " << fPtr << "\n";
#endif
        return ExportsMapper::RES_FORWARDED;
    }

    ULONGLONG callVa = callRVA + moduleBase;
    if (!peconv::validate_ptr((BYTE*)moduleBase, moduleSize, (BYTE*)callVa, sizeof(ULONGLONG))) {
        // this may happen when the function was forwarded and it is already filled
#ifdef _DEBUG
        std::cout << "Validation failed:  " << currFunc.toString() << "\n";
#endif
        return ExportsMapper::RES_INVALID;
    }
    //not forwarded, simple case:
    add_to_maps(callVa, currFunc);
    return ExportsMapper::RES_MAPPED;
}

size_t ExportsMapper::add_to_lookup(std::string moduleName, HMODULE modulePtr, ULONGLONG moduleBase)
{
    IMAGE_EXPORT_DIRECTORY* exp = get_export_directory(modulePtr);
    if (exp == NULL) {
        return 0;
    }
    size_t module_size = peconv::get_image_size(reinterpret_cast<const PBYTE>(modulePtr));
    if (!is_valid_export_table(exp, modulePtr, module_size)) {
        return 0;
    }
    std::string dllName = get_dll_shortname(moduleName);
    this->dll_shortname_to_path[dllName] = moduleName;

    std::map<PDWORD, DWORD> va_to_ord;
    size_t functCount = make_ord_lookup_tables(modulePtr, module_size, va_to_ord);

    //go through names:
    
    size_t forwarded_ctr = 0;
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    size_t mapped_ctr = 0;

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));
        if (*funcRVA == 0) {
#ifdef _DEBUG
            std::cout << ">>> Skipping 0 function address at RVA:" << std::hex << (BYTE*)funcRVA - (BYTE*)modulePtr << "(name)\n";
#endif
            //skip if the function RVA is 0 (empty export)
            continue;
        }

        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        if (!peconv::validate_ptr(modulePtr, module_size, name, sizeof(char))) break;

        DWORD funcOrd = get_ordinal(funcRVA, va_to_ord);
        DWORD callRVA = *funcRVA;
        ExportedFunc currFunc(dllName, name, funcOrd);

        int res = add_function_to_lookup(modulePtr, moduleBase, module_size, currFunc, callRVA);
        if (res == ExportsMapper::RES_FORWARDED) forwarded_ctr++;
        if (res == ExportsMapper::RES_MAPPED) mapped_ctr++;
    }
    //go through unnamed functions exported by ordinals:
    std::map<PDWORD, DWORD>::iterator ord_itr = va_to_ord.begin();
    for (;ord_itr != va_to_ord.end(); ++ord_itr) {

        DWORD* funcRVA = ord_itr->first;
        DWORD callRVA = *funcRVA;
        ExportedFunc currFunc(dllName, ord_itr->second);

        int res = add_function_to_lookup(modulePtr, moduleBase, module_size, currFunc, callRVA);
        if (res == ExportsMapper::RES_FORWARDED) forwarded_ctr++;
        if (res == ExportsMapper::RES_MAPPED) mapped_ctr++;
    }
#ifdef _DEBUG
    std::cout << "Finished exports parsing, mapped: "<< mapped_ctr << " forwarded: " << forwarded_ctr  << std::endl;
#endif
    return mapped_ctr;
}
