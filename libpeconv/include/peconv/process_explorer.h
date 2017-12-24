#pragma once

#include "Windows.h"

#include <map>

namespace peconv {

    struct LoadedModule {

        LoadedModule(ULONGLONG _start, ULONGLONG _end, std::string _path, DWORD _pid)
            :start(_start), end(_end), path(_path), process_id(_pid)
        {
        }

        ~LoadedModule()
        {
        }

        bool operator<(LoadedModule other) const
        {
            return this->start < other.start;
        }

        bool is_remote()
        {
            return process_id != GetCurrentProcessId();
        }

        std::string path;
        ULONGLONG start;
        ULONGLONG end;
        DWORD process_id;
    };

    struct ProcessModules {
        ProcessModules (DWORD _pid)
            : process_id(_pid)
        {
        }
        
        ~ProcessModules()
        {
            delete_mapping();
        }

        void delete_mapping();
        size_t load_mapping();
        const LoadedModule* get_module_containing(ULONGLONG address);

        std::map<ULONGLONG, LoadedModule*> modulesMap;
        DWORD process_id;
    };

    //wrapper - works for a current process:
    HMODULE get_module_containing(ULONGLONG address);

}; //namespace peconv
