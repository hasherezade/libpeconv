#pragma once

#include <Windows.h>
#include "function_resolver.h"

#include <iostream>
#include <string>
#include <map>


namespace peconv {

    //for hooking IAT:
    class hooking_func_resolver : peconv::default_func_resolver {
        public:

        void add_hook(std::string name, FARPROC function ) 
        {
            hooks_map[name] = function;
        }

        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);

        private:
        std::map<std::string, FARPROC> hooks_map;
    };

    //for installing inline hooks:
    void redirect_to_local64(void *ptr, ULONGLONG new_offset);

    void redirect_to_local32(void *ptr, DWORD new_offset);

    //replaces a target address of JMP or CALL <DWORD>
    bool replace_target(BYTE *ptr, ULONGLONG dest_addr);

};//namespace peconv
