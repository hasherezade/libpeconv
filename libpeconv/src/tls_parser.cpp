#include "peconv/tls_parser.h"

#include "peconv/pe_hdrs_helper.h"
#include <iostream>

namespace peconv {

    // convert a virtual address (given as VA or RVA) to RVA
    bool virtual_addr_to_rva(IN const ULONGLONG img_base, IN const DWORD img_size, IN ULONGLONG callback_addr, OUT DWORD &callback_rva)
    {
        if (!img_size || !callback_addr) return false;

        //check if VA:
        if (callback_addr >= img_base && callback_addr < (img_base + img_size)) {
            callback_rva = MASK_TO_DWORD(callback_addr - img_base);
            return true;
        }
        if (callback_addr < img_size) {
            callback_rva = MASK_TO_DWORD(callback_addr);
            return true;
        }
        // out of scope address
        return false;
    }

    template <typename FIELD_T>
    size_t fetch_callbacks_list(IN PVOID modulePtr, IN size_t moduleSize, IN DWORD callbacks_rva, OUT std::vector<DWORD> &callbacks_RVAs)
    {
        FIELD_T* callbacks_list_ptr = (FIELD_T*)(callbacks_rva + (BYTE*)modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, callbacks_list_ptr, sizeof(FIELD_T))) {
            return 0;
        }

        const ULONGLONG img_base = (ULONGLONG)modulePtr;
        const DWORD img_size = peconv::get_image_size((BYTE*)modulePtr);
        size_t counter = 0;
        for (FIELD_T *next_callback = callbacks_list_ptr; 
            validate_ptr(modulePtr, moduleSize, next_callback, sizeof(FIELD_T));
            next_callback++)
        {
            FIELD_T value = *next_callback;
            if (value == 0) break;

            DWORD callback_rva = 0;
            if (!virtual_addr_to_rva(img_base, img_size, value, callback_rva)) {
                // in some cases, TLS callbacks can lead to functions in other modules: we want to skip those,
                // keeping only addresses that are in the current PE scope
                continue;
            }
            callbacks_RVAs.push_back(callback_rva);
            counter++;
        }
        return counter;
    }
};

size_t peconv::list_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize, OUT std::vector<DWORD> &callbacks_RVAs)
{
    const ULONGLONG img_base = (ULONGLONG)modulePtr;
    const DWORD img_size = peconv::get_image_size((BYTE*)modulePtr);
    if (!img_size) return 0; // invalid image

    if (moduleSize == 0) {
        moduleSize = img_size;
    }
    IMAGE_TLS_DIRECTORY* tls_dir = peconv::get_type_directory<IMAGE_TLS_DIRECTORY>((HMODULE)modulePtr, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls_dir) return 0;

    ULONGLONG callbacks_addr = tls_dir->AddressOfCallBacks;
    if (!callbacks_addr) return 0;
#ifdef _DEBUG
    std::cout << "TLS Callbacks Table: " << std::hex << callbacks_addr << std::endl;
#endif
    DWORD callbacks_rva = 0;
    if (!virtual_addr_to_rva(img_base, img_size, callbacks_addr, callbacks_rva)) return 0;
#ifdef _DEBUG
    std::cout << "TLS Callbacks RVA: " << std::hex << callbacks_rva << std::endl;
#endif
    size_t counter = 0;
    if (peconv::is64bit((BYTE*)modulePtr)) {
        counter = fetch_callbacks_list<ULONGLONG>(modulePtr, moduleSize, callbacks_rva, callbacks_RVAs);
    }
    else {
        counter = fetch_callbacks_list<DWORD>(modulePtr, moduleSize, callbacks_rva, callbacks_RVAs);
    }
    return counter;
}

size_t peconv::run_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize, IN DWORD dwReason)
{
    if (moduleSize == 0) {
        moduleSize = peconv::get_image_size((BYTE*)modulePtr);
    }
    std::vector<DWORD> callbacksRVAs;
    if (!peconv::list_tls_callbacks(modulePtr, moduleSize, callbacksRVAs)) {
        return 0;
    }
    std::vector<DWORD>::iterator itr;
    size_t i = 0;
    for (itr = callbacksRVAs.begin(); itr != callbacksRVAs.end(); ++itr, i++) {
        DWORD rva = *itr;
#ifdef _DEBUG
        std::cout << std::hex << "TLS RVA:" << rva << std::endl;
#endif
        ULONG_PTR callback_va = rva + (ULONG_PTR)modulePtr;

        void(NTAPI *callback_func)(PVOID DllHandle, DWORD dwReason, PVOID) = (void(NTAPI *)(PVOID, DWORD, PVOID)) (callback_va);
#ifdef _DEBUG
        std::cout << "Calling TLS callback[" << i << "]:" << std::endl;
#endif
        callback_func(modulePtr, dwReason, NULL);
    }
    return i;
}
