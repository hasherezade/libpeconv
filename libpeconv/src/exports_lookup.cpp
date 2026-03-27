#include "peconv/exports_lookup.h"
#include "peconv/util.h"

#include "peconv/logger.h"

/*
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(c1) c1 = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1;
#endif

namespace {

    bool is_wanted_func(LPCSTR curr_name, LPCSTR wanted_name)
    {
        if (curr_name == NULL || wanted_name == NULL) return false;

        size_t wanted_name_len = strlen(wanted_name);
        size_t curr_name_len = strlen(curr_name);

        if (curr_name_len != wanted_name_len) return false;

        for (size_t i = 0; i < wanted_name_len; i++) {
            char c1 = curr_name[i];
            char c2 = wanted_name[i];
            TO_LOWERCASE(c1);
            TO_LOWERCASE(c2);
            if (c1 != c2) return false;
        }
        return true;
    }

    bool is_ordinal(IMAGE_EXPORT_DIRECTORY* exp, LPCSTR func_name)
    {
        ULONGLONG base = exp->Base;
        ULONGLONG max_ord = base + exp->NumberOfFunctions;
        ULONGLONG name_ptr_val = (ULONGLONG)func_name;
        if (name_ptr_val >= base && name_ptr_val < max_ord) {
            return true;
        }
        return false;
    }

    FARPROC get_export_by_ord(LPVOID modulePtr, IMAGE_EXPORT_DIRECTORY* exp, DWORD wanted_ordinal)
    {
        SIZE_T functCount = exp->NumberOfFunctions;
        DWORD funcsListRVA = exp->AddressOfFunctions;
        DWORD ordBase = exp->Base;

        const size_t modSize = peconv::get_image_size((BYTE*)modulePtr);

        //go through names:
        for (DWORD i = 0; i < functCount; i++) {
            DWORD ordinal = ordBase + i;
            if (ordinal != wanted_ordinal) continue;

            DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)modulePtr + i * sizeof(DWORD));
            if (!peconv::validate_ptr((LPVOID)modulePtr, modSize, funcRVA, sizeof(DWORD))) {
                LOG_ERROR("Invalid RVA of exported function");
                return NULL;
            }
            BYTE* fPtr = (BYTE*)modulePtr + (*funcRVA); //pointer to the function
            if (!peconv::validate_ptr((LPVOID)modulePtr, modSize, fPtr, 1)) {
                LOG_ERROR("Invalid pointer to exported function");
                return NULL;
            }
            if (peconv::is_valid_string(modulePtr, modSize, fPtr) && peconv::forwarder_name_len(fPtr) > 1) {
                LOG_WARNING("Forwarded function: [%lu -> %p] cannot be resolved.", wanted_ordinal, fPtr);
                return NULL; // this function is forwarded, cannot be resolved
            }
            return (FARPROC)fPtr; //return the pointer to the found function
        }
        return NULL;
    }
};

size_t peconv::get_exported_names(LPVOID modulePtr, std::vector<std::string> &names_list)
{
    const size_t modSize = peconv::get_image_size((const BYTE*)modulePtr);
    if (!modSize) return 0;

    IMAGE_EXPORT_DIRECTORY* exp = peconv::get_export_directory((HMODULE) modulePtr);
    if (!exp || !validate_ptr(modulePtr, modSize, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        return 0;
    }

    SIZE_T namesCount = exp->NumberOfNames;
    DWORD funcNamesListRVA = exp->AddressOfNames;

    //go through names:
    DWORD* nameRVAs = (DWORD*)(funcNamesListRVA + (ULONG_PTR)modulePtr);
    SIZE_T i = 0;
    for (i = 0; i < namesCount; i++) {
        if (!validate_ptr(modulePtr, modSize, &nameRVAs[i], sizeof(DWORD))) {
            break;// this should not happen. maybe the PE file is corrupt?
        }
        DWORD nameRVA = nameRVAs[i];
        if (!nameRVA) {
            continue;
        }
        LPSTR name = (LPSTR)(nameRVA + (BYTE*) modulePtr);
        if (!is_valid_string(modulePtr, modSize, name)) {
            break;// this should not happen. maybe the PE file is corrupt?
        }
        names_list.push_back(name);
    }
    return i;
}

//WARNING: doesn't work for the forwarded functions.
FARPROC peconv::get_exported_func(LPVOID modulePtr, LPCSTR wanted_name)
{
    const size_t modSize = peconv::get_image_size((const BYTE*)modulePtr);
    if (!modSize) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exp = peconv::get_export_directory((HMODULE) modulePtr);
    if (!exp || !validate_ptr(modulePtr, modSize, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        return nullptr;
    }

    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    if (is_ordinal(exp, wanted_name)) {
        LOG_DEBUG("Getting function by ordinal.");
        const DWORD ordinal = MASK_TO_DWORD((ULONG_PTR)wanted_name);
        return get_export_by_ord(modulePtr, exp, ordinal);
    }
    if (peconv::is_bad_read_ptr(wanted_name, 1)) { // wanted_name is not in supplied module, so we can't check it against the module bounds
        LOG_ERROR("Invalid pointer to the name.");
        return nullptr;
    }
    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        if (!validate_ptr(modulePtr, modSize, nameRVA, sizeof(DWORD)) 
            || !validate_ptr(modulePtr, modSize, nameIndex, sizeof(WORD)))
        {
            LOG_ERROR("Invalid pointer to exported name RVA or index");
            return nullptr;
        }
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));
        if (!validate_ptr(modulePtr, modSize, funcRVA, sizeof(DWORD))) {
            LOG_ERROR("Invalid pointer to exported function RVA");
            return nullptr;
        }
        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        if (!peconv::validate_ptr(modulePtr, modSize, name, 1)) {
            LOG_ERROR("Invalid pointer to exported function name");
            return nullptr;
        }
        if (!is_wanted_func(name, wanted_name)) {
            continue; //this is not the function we are looking for
        }
        BYTE* fPtr = (BYTE*)modulePtr + (*funcRVA); //pointer to the function
        if (!peconv::validate_ptr(modulePtr, modSize, (LPVOID)fPtr, 1)) {
            LOG_ERROR("Invalid pointer to exported function");
            return NULL;
        }
        if (is_valid_string(modulePtr, modSize, fPtr) && forwarder_name_len(fPtr) > 1) {
            LOG_WARNING("Forwarded function: [%s -> %p] cannot be resolved.", name, fPtr);
            return nullptr; // this function is forwarded, cannot be resolved
        }
        return (FARPROC) fPtr; //return the pointer to the found function
    }
    //function not found
    LOG_WARNING("Function not found.");
    return nullptr;
}

FARPROC peconv::export_based_resolver::resolve_func(LPCSTR lib_name, LPCSTR func_name)
{
    HMODULE libBasePtr = load_library(lib_name);
    if (libBasePtr == NULL) {
        LOG_ERROR("Could not load the library.");
        return NULL;
    }

    FARPROC hProc = get_exported_func(libBasePtr, func_name);
    if (!hProc) {
        LOG_WARNING("Could could not get function from exports. Falling back to the default resolver.");
        hProc = default_func_resolver::resolve_func(lib_name, func_name);
        if (!hProc) {
            LOG_ERROR("Loading function from %s failed.", lib_name);
        }
    }
    return hProc;
}

LPSTR peconv::read_dll_name(HMODULE modulePtr)
{
    const size_t modSize = peconv::get_image_size((const BYTE*)modulePtr);
    if (!modSize) {
        return nullptr;
    }
    IMAGE_EXPORT_DIRECTORY* exp = get_export_directory(modulePtr);
    if (!exp || !validate_ptr(modulePtr, modSize, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        return nullptr;
    }
    const LPSTR module_name = (char*)((ULONGLONG)modulePtr + exp->Name);
    if (is_valid_string(modulePtr, modSize, module_name) && forwarder_name_len((BYTE*)module_name) > 1) {
        return module_name;
    }
    return nullptr;
}
