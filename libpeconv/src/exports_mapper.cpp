#include "peconv/exports_mapper.h"
#include <algorithm>

using namespace peconv;

size_t ExportsMapper::make_ord_lookup_tables(PVOID modulePtr, 
                                std::map<ULONGLONG, DWORD> &va_to_ord
                                )
{
    size_t forwarded_ctr = 0;

    IMAGE_EXPORT_DIRECTORY* exp = peconv::get_image_export_dir((HMODULE) modulePtr);
    if (exp == NULL) return NULL;

    SIZE_T functCount = exp->NumberOfFunctions;
	DWORD funcsListRVA = exp->AddressOfFunctions;
	DWORD ordBase = exp->Base;

    //go through names:
    for (SIZE_T i = 0; i < functCount; i++) {
		DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
		DWORD ordinal = ordBase + i;
        va_to_ord[(ULONGLONG)funcRVA] = ordinal;
    }
    return functCount - forwarded_ctr;
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

size_t ExportsMapper::addToLookupTables(std::string moduleName, HMODULE modulePtr)
{
    IMAGE_EXPORT_DIRECTORY* exp = get_image_export_dir(modulePtr);
    if (exp == NULL) {
        return 0;
    }
    std::map<ULONGLONG, DWORD> va_to_ord;
    size_t ord = make_ord_lookup_tables(modulePtr, va_to_ord);

    std::string dllName = getDllName(moduleName);
    size_t forwarded_ctr = 0;

    SIZE_T namesCount = exp->NumberOfNames;
    char* module_name = (char*)((ULONGLONG)modulePtr + exp->Name);

    std::map<DWORD, char*> rva_to_name;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));
        DWORD funcOrd = va_to_ord[(ULONGLONG)funcRVA];
       
        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        ExportedFunc currFunc(dllName, name, funcOrd);

        BYTE* fPtr = (BYTE*) modulePtr + (*funcRVA);
        if (forwarderNameLen(fPtr) > 1) {
            std::string forwardedFunc = formatDllFunc((char*)fPtr);
            if (forwardedFunc.length() == 0) {
                continue;
            }

            ExportedFunc forwarder(forwardedFunc);
            forwarders_lookup[forwarder].insert(currFunc);

            if (func_to_va[forwarder] != 0) {
                ULONGLONG va = func_to_va[forwarder];
                va_to_func[va].insert(currFunc);
                func_to_va[currFunc] = va;
            }
            forwarded_ctr++;
            continue;
        } else {
            //not forwarded, simple case:
            ULONGLONG va = (ULONGLONG) modulePtr + (*funcRVA);
            va_to_func[va].insert(currFunc);
            func_to_va[currFunc] = va;

            //resolve forwarders of this function (if any):
            resolve_forwarders(va, currFunc);
        }
    }
    return forwarded_ctr;
}
