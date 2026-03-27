#include "peconv/tls_parser.h"

#include "peconv/pe_hdrs_helper.h"
#include "peconv/logger.h"

namespace peconv {


    template <typename FIELD_T>
    size_t fetch_callbacks_list(IN PVOID modulePtr, IN size_t moduleSize, IN DWORD callbacks_rva, OUT std::vector<ULONGLONG> &tls_callbacks)
    {
        FIELD_T* callbacks_list_ptr = (FIELD_T*)(callbacks_rva + (BYTE*)modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, callbacks_list_ptr, sizeof(FIELD_T))) {
            return 0;
        }
        size_t counter = 0;
        for (FIELD_T *next_callback = callbacks_list_ptr; 
            validate_ptr(modulePtr, moduleSize, next_callback, sizeof(FIELD_T));
            next_callback++)
        {
            FIELD_T value = *next_callback;
            if (value == 0) break;

            tls_callbacks.push_back(value);
            counter++;
        }
        return counter;
    }
};


bool peconv::virtual_addr_to_rva(IN const ULONGLONG img_base, IN const DWORD img_size, IN ULONGLONG callback_addr, OUT DWORD &callback_rva)
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

size_t peconv::list_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize, OUT std::vector<ULONGLONG> &tls_callbacks)
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
    LOG_DEBUG("TLS Callbacks Table: 0x%llx.", (unsigned long long)callbacks_addr);
    DWORD callbacks_rva = 0;
    if (!virtual_addr_to_rva(img_base, img_size, callbacks_addr, callbacks_rva)) return 0;
    LOG_DEBUG("TLS Callbacks RVA: 0x%llx.", (unsigned long long)callbacks_rva);
    size_t counter = 0;
    if (peconv::is64bit((BYTE*)modulePtr)) {
        counter = fetch_callbacks_list<ULONGLONG>(modulePtr, moduleSize, callbacks_rva, tls_callbacks);
    }
    else {
        counter = fetch_callbacks_list<DWORD>(modulePtr, moduleSize, callbacks_rva, tls_callbacks);
    }
    return counter;
}

size_t peconv::run_tls_callbacks(IN PVOID modulePtr, IN size_t moduleSize, IN DWORD dwReason)
{
    const DWORD img_size = peconv::get_image_size((BYTE*)modulePtr);
    if (moduleSize == 0) {
        moduleSize = img_size;
    }
    std::vector<ULONGLONG> tls_callbacks;
    if (!peconv::list_tls_callbacks(modulePtr, moduleSize, tls_callbacks)) {
        return 0;
    }
    std::vector<ULONGLONG>::iterator itr;
    size_t i = 0;
    for (itr = tls_callbacks.begin(); itr != tls_callbacks.end(); ++itr, i++) {
        ULONGLONG callback_addr = *itr;
        DWORD rva = 0; //TLS callback can be defined as RVA or VA, so make sure it is in a consistent format...
        if (!peconv::virtual_addr_to_rva((ULONG_PTR)modulePtr, img_size, callback_addr, rva)) {
            // in some cases, TLS callbacks can lead to functions in other modules: we want to skip those,
            // keeping only addresses that are in the current PE scope
            continue;
        }
        LOG_DEBUG("TLS RVA: 0x%llx.", (unsigned long long)rva);
        ULONG_PTR callback_va = rva + (ULONG_PTR)modulePtr;
        if (!validate_ptr(modulePtr, moduleSize, (BYTE*)callback_va, sizeof(BYTE))) {
            // make sure that the address is valid
            continue;
        }
        void(NTAPI *callback_func)(PVOID DllHandle, DWORD dwReason, PVOID) = (void(NTAPI *)(PVOID, DWORD, PVOID)) (callback_va);
        LOG_INFO("Calling TLS callback[%zu].", i);
        callback_func(modulePtr, dwReason, NULL);
    }
    return i;
}
