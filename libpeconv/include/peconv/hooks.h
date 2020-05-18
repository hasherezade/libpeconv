/**
* @file
* @brief   Functions related to hooking the loaded PE. Reditecting/replacing a functions with another.
*/

#pragma once

#include <windows.h>
#include "function_resolver.h"

#include <iostream>
#include <string>
#include <map>
#include "peconv/buffer_util.h"

namespace peconv {

    /**
    A buffer storing a binary patch, that can be applied on a module. Used as a restorable backup in case of function patching.
    */
    class PatchBackup {
    public:
        /**
        Creates an empty backup.
        */
        PatchBackup()
            : buffer(nullptr), bufferSize(0), sourcePtr(nullptr)
        {
        }

        ~PatchBackup() {
            deleteBackup();
        }

        /**
        Destroys the backup and resets internal fields.
        */
        void deleteBackup()
        {
            if (buffer) {
                delete[] buffer;
                bufferSize = 0;
                sourcePtr = nullptr;
            }
        }

        /**
        Reads bytes from the binary to the backup. The source buffer must be within the current process.
        */
        bool makeBackup(BYTE *patch_ptr, size_t patch_size);

        /**
        Applies the backup back to the pointer from which it was read.
        */
        bool applyBackup();

        /**
        Checks if the buffer was filled.
        */
        bool isBackup()
        {
            return buffer != nullptr;
        }

    protected:
        BYTE *buffer;
        size_t bufferSize;

        BYTE *sourcePtr;
    };


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
    Installs inline hook at the given ptr. Returns the number of bytes overwriten.
    64 bit version.
    \param ptr : pointer to the function to be replaced
    \param new_offset : VA of the new function
    \param backup : (optional) backup that can be used to reverse the changes
    \return size of the applied patch
    */
    size_t redirect_to_local64(void *ptr, ULONGLONG new_offset, PatchBackup* backup = nullptr);

    /**
    Installs inline hook at the given ptr. Returns the number of bytes overwriten.
    32 bit version.
    \param ptr : pointer to the function to be replaced
    \param new_offset : VA of the new function
    \param backup : (optional) backup that can be used to reverse the changes
    \return size of the applied patch
    */
    size_t redirect_to_local32(void *ptr, DWORD new_offset, PatchBackup* backup = nullptr);

    /**
    Installs inline hook at the given ptr. Returns the number of bytes overwriten.
    Uses bitness of the current applications for the bitness of the intalled hook.
    \param ptr : pointer to the function to be replaced
    \param new_function_ptr : pointer to the new function
    \param backup : (optional) backup that can be used to reverse the changes
    \return size of the applied patch
    */
    size_t redirect_to_local(void *ptr, void* new_function_ptr, PatchBackup* backup = nullptr);

    /**
    Replaces a target address of JMP [DWORD] or CALL [DWORD]
    */
    bool replace_target(BYTE *ptr, ULONGLONG dest_addr);

};//namespace peconv
