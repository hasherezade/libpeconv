#include "peconv/tls_helper.h"

#include "peconv/pe_hdrs_helper.h"
#include <iostream>

namespace peconv {

    // convert a virtual address (given as VA or RVA) to RVA
    DWORD virtual_addr_to_rva(const ULONGLONG img_base, const DWORD img_size, ULONGLONG callbacks_addr)
    {
        if (!img_size || !callbacks_addr) return 0;

        //check if VA:
        if (callbacks_addr >= img_base && callbacks_addr < (img_base + img_size)) {
            const DWORD callbacks_rva = MASK_TO_DWORD(callbacks_addr - img_base);
            return callbacks_rva;
        }
        return MASK_TO_DWORD(callbacks_addr);
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

            std::cout << "NExt TLS Callbacks: " << std::hex << value  << std::endl;
            DWORD callback_rva = virtual_addr_to_rva(img_base, img_size, value);
            callbacks_RVAs.push_back(callback_rva);
            counter++;
        }
        return counter;
    }
};

size_t peconv::list_tls_callbacks(PVOID modulePtr, size_t moduleSize, std::vector<DWORD> &callbacks_RVAs)
{
    const ULONGLONG img_base = (ULONGLONG)modulePtr;
    const DWORD img_size = peconv::get_image_size((BYTE*)modulePtr);
    if (!img_size) return 0; // invalid image

    IMAGE_TLS_DIRECTORY* tls_dir = peconv::get_type_directory<IMAGE_TLS_DIRECTORY>((HMODULE)modulePtr, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls_dir) return 0;

    ULONGLONG callbacks_addr = tls_dir->AddressOfCallBacks;
    if (!callbacks_addr) return 0;

    std::cout << "TLS Callbacks Table: " << std::hex << callbacks_addr << std::endl;

    DWORD callbacks_rva = virtual_addr_to_rva(img_base, img_size, callbacks_addr);
    if (!callbacks_rva) return 0;

    std::cout << "TLS Callbacks RVA: " << std::hex << callbacks_rva << std::endl;

    size_t counter = 0;
    if (peconv::is64bit((BYTE*)modulePtr)) {
        counter = fetch_callbacks_list<ULONGLONG>(modulePtr, moduleSize, callbacks_rva, callbacks_RVAs);
    }
    else {
        counter = fetch_callbacks_list<DWORD>(modulePtr, moduleSize, callbacks_rva, callbacks_RVAs);
    }
    return counter;
}

size_t peconv::run_tls_callbacks(PVOID modulePtr, size_t moduleSize)
{
    std::vector<DWORD> callbacksRVAs;
    if (!peconv::list_tls_callbacks(modulePtr, moduleSize, callbacksRVAs)) {
        return 0;
    }
    std::vector<DWORD>::iterator itr;
    size_t i = 0;
    for (itr = callbacksRVAs.begin(); itr != callbacksRVAs.end(); ++itr, i++) {
        DWORD rva = *itr;
        std::cout << std::hex << "TLS RVA:" << rva << std::endl;
        ULONG_PTR callback_va = rva + (ULONG_PTR)modulePtr;

        void(NTAPI *callback_func)(PVOID DllHandle, DWORD dwReason, PVOID) = (void(NTAPI *)(PVOID, DWORD, PVOID)) (callback_va);
        std::cout << "Calling TLS callback[" << i << "]:" << std::endl;
        callback_func(modulePtr, 1, NULL);
    }
}
