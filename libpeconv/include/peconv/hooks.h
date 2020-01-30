/**
* @file
* @brief   Functions related to hooking the loaded PE. Reditecting/replacing a functions with another.
*/

#pragma once

#include <Windows.h>
#include "function_resolver.h"

#include <iostream>
#include <string>
#include <map>
#include "peconv/buffer_util.h"

namespace peconv {
    class PatchBackup {
    public:

        PatchBackup()
            : buffer(nullptr), bufferSize(0)
        {
        }

        ~PatchBackup() {
            deleteBackup();
        }

        void deleteBackup()
        {
            if (buffer) {
                delete[] buffer;
                bufferSize = 0;
            }
        }

        bool makeBackup(BYTE *patch_ptr, size_t patch_size)
        {
            if (!patch_ptr) {
                return false;
            }
            deleteBackup();
            this->sourcePtr = patch_ptr;
            this->buffer = new BYTE[patch_size];
            this->bufferSize = patch_size;

            memcpy(buffer, patch_ptr, patch_size);
            return true;
        }

        bool applyBackup()
        {
            if (!isBackup()) {
                return false;
            }
            DWORD oldProtect = 0;
            if (!VirtualProtect((LPVOID)sourcePtr, bufferSize, PAGE_READWRITE, &oldProtect)) {
                return false;
            }
            memcpy(sourcePtr, buffer, bufferSize);
            VirtualProtect((LPVOID)sourcePtr, bufferSize, oldProtect, &oldProtect);
            return true;
        }

        bool isBackup()
        {
            return buffer != nullptr;
        }

    protected:

        BYTE *buffer;
        size_t bufferSize;

        BYTE * sourcePtr;
    };
};

namespace peconv {

    /**
    A functions resolver that can be used for hooking IAT. Allows for defining functions that are supposed to be replaced.
    */
    class hooking_func_resolver : peconv::default_func_resolver {
    public:
        /**
        Define a function that will be replaced.
        \param name : a name of the function that will be replaced
        \param function : an address of the replacement function
        */
        void add_hook(std::string name, FARPROC function)
        {
            hooks_map[name] = function;
        }

        /**
        Get the address (VA) of the function with the given name, from the given DLL. If the function was hooked, it retrieves the address of the replacement function instead.
        \param func_name : the name of the function
        \param lib_name : the name of the DLL
        \return Virtual Address of the exported function, or the address of the replacement function.
        */
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);

    private:
        std::map<std::string, FARPROC> hooks_map;
    };

    /**
    Installs inline hook at the given ptr. Returns the number of bytes overwriten. 64 bit version.
    */
    size_t redirect_to_local64(void *ptr, ULONGLONG new_offset, PatchBackup* backup = nullptr);

    /**
    Installs inline hook at the given ptr. Returns the number of bytes overwriten. 32 bit version.
    */
    size_t redirect_to_local32(void *ptr, DWORD new_offset, PatchBackup* backup = nullptr);

    /**
    Replaces a target address of JMP <DWORD> or CALL <DWORD>
    */
    bool replace_target(BYTE *ptr, ULONGLONG dest_addr);

};//namespace peconv
