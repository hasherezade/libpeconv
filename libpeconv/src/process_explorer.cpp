#include "peconv/process_explorer.h"

#include <iostream>

size_t peconv::enum_modules_in_process(std::map<ULONGLONG, MODULEENTRY32> &modulesMap, DWORD process_id)
{
    if (process_id == 0) {
        process_id = GetCurrentProcessId();
    }
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
    MODULEENTRY32 module_entry = { 0 };
    module_entry.dwSize = sizeof(module_entry);
	
    if (!Module32First(hProcessSnapShot, &module_entry)) {
        std::cerr << "[ERROR] Fetching modules failed!" << std::endl;
        return 0;
    }
    size_t modules = 1;
    modulesMap[(ULONGLONG) module_entry.modBaseAddr] = module_entry;

    while (Module32Next(hProcessSnapShot, &module_entry)) {
        modulesMap[(ULONGLONG) module_entry.modBaseAddr] = module_entry;
        modules++;
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return modules;
}

HMODULE peconv::get_module_containing(ULONGLONG address, DWORD process_id)
{
    std::map<ULONGLONG, MODULEENTRY32> modulesMap;
    size_t modules_count = peconv::enum_modules_in_process(modulesMap, process_id);
    if (modules_count == 0) {
        return NULL;
    }
    std::map<ULONGLONG, MODULEENTRY32>::iterator itr = modulesMap.begin();
    for (; itr != modulesMap.end(); itr++ ) {
        ULONGLONG start = itr->first;
        ULONGLONG end =  start + itr->second.modBaseSize;

        if (address >= start && address < end) {
            std::cout << "[*] Module:" << itr->second.szExePath << std::endl;
            return (HMODULE) start;
        }
    }
    return NULL;
}