#include "peconv/exports_mapper.h"
#include <algorithm>
#include <iostream>

using namespace peconv;

ULONGLONG rebase_va(ULONGLONG va, ULONGLONG currBase, ULONGLONG targetBase)
{
    if (currBase == targetBase) {
        return va;
    }
    ULONGLONG rva =  va - (ULONGLONG) currBase;
    return rva + targetBase;
}

size_t ExportsMapper::make_ord_lookup_tables(PVOID modulePtr, 
                                             std::map<PDWORD, DWORD> &va_to_ord
                                             )
{
    IMAGE_EXPORT_DIRECTORY* exp = peconv::get_export_directory((HMODULE) modulePtr);
    if (exp == NULL) return NULL;

    SIZE_T functCount = exp->NumberOfFunctions;
    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD ordBase = exp->Base;

    //go through names:
    for (DWORD i = 0; i < functCount; i++) {
        DWORD* recordRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));

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
        for (sItr = fItr->second.begin(); sItr != fItr->second.end(); sItr++) {
            //printf("-> %s\n", sItr->c_str());
            va_to_func[va].insert(*sItr);
            func_to_va[*sItr] = va;
            resolved++;
        }
    }
    return resolved;
}

bool ExportsMapper::add_forwarded(PBYTE fPtr, ExportedFunc &currFunc)
{
    if (fPtr == nullptr) return false;

    if (peconv::forwarder_name_len(fPtr) < 1) {
        return false; //not forwarded
    }
    std::string forwardedFunc = format_dll_func((char*)fPtr);
    if (forwardedFunc.length() == 0) {
        return false; //not forwarded
    }

    ExportedFunc forwarder(forwardedFunc);
    forwarders_lookup[forwarder].insert(currFunc);

    if (func_to_va[forwarder] != 0) {
        ULONGLONG va = func_to_va[forwarder];
        va_to_func[va].insert(currFunc);
        func_to_va[currFunc] = va;
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
    va_to_func[va].insert(currFunc);
    func_to_va[currFunc] = va;
    resolve_forwarders(va, currFunc);
    return true;
}

size_t ExportsMapper::add_to_lookup(std::string moduleName, HMODULE modulePtr, ULONGLONG moduleBase)
{
    IMAGE_EXPORT_DIRECTORY* exp = get_export_directory(modulePtr);
    if (exp == NULL) {
        return 0;
    }
    size_t module_size = peconv::get_image_size(reinterpret_cast<const PBYTE>(modulePtr));

    size_t forwarded_ctr = 0;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    if (!peconv::validate_ptr(modulePtr, module_size, funcsListRVA + modulePtr, sizeof(DWORD))) return 0;
    if (!peconv::validate_ptr(modulePtr, module_size, funcNamesListRVA + modulePtr, sizeof(DWORD))) return 0;
    if (!peconv::validate_ptr(modulePtr, module_size, namesOrdsListRVA + modulePtr, sizeof(DWORD))) return 0;

    char* module_name = (char*)((ULONGLONG)modulePtr + exp->Name);
    if (!peconv::validate_ptr(modulePtr, module_size, module_name, sizeof(char))) return 0;

    std::string dllName = get_dll_name(moduleName);

    std::map<PDWORD, DWORD> va_to_ord;
     size_t functCount = make_ord_lookup_tables(modulePtr, va_to_ord);

     std::map<DWORD, char*> rva_to_name;
    //go through names:
     
     SIZE_T namesCount = exp->NumberOfNames;

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));

        DWORD funcOrd = get_ordinal(funcRVA, va_to_ord);

        DWORD callRVA = *funcRVA;
        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        if (!peconv::validate_ptr(modulePtr, module_size, name, sizeof(char))) return 0;
        ExportedFunc currFunc(dllName, name, funcOrd);

        BYTE* fPtr = (BYTE*) modulePtr + callRVA;
        if (add_forwarded(fPtr, currFunc)) {
            forwarded_ctr++;
        } else {
            //not forwarded, simple case:
            ULONGLONG callVa = rebase_va((ULONGLONG) fPtr, (ULONGLONG)modulePtr, moduleBase);
            add_to_maps(callVa, currFunc);
        }
    }

    //go through unnamed functions exported by ordinals:
    std::map<PDWORD, DWORD>::iterator ord_itr = va_to_ord.begin();
    for (;ord_itr != va_to_ord.end(); ord_itr++) {

        ExportedFunc currFunc(dllName, ord_itr->second);

        DWORD* funcRVA = ord_itr->first;
        DWORD callRVA = *funcRVA;

        PBYTE fPtr = (PBYTE) modulePtr + callRVA;
        if (add_forwarded(fPtr, currFunc)) {
            forwarded_ctr++;
        } else {
            ULONGLONG callVa = rebase_va((ULONGLONG) fPtr, (ULONGLONG)modulePtr, moduleBase);
            //std::cout << std::hex << callVa << " : " << currFunc.toString() << std::endl;
            add_to_maps(callVa, currFunc);
        }
    }
    return functCount - forwarded_ctr;
}
