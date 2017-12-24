#include "peconv/process_explorer.h"

#include <string>
#include <iostream>

#include <TlHelp32.h>

size_t peconv::ProcessModules::load_mapping()
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
    LoadedModule *lModule = new LoadedModule(
        (ULONGLONG) module_entry.modBaseAddr, 
        (ULONGLONG) module_entry.modBaseAddr + module_entry.modBaseSize,
        module_entry.szExePath,
        process_id
        );
    modulesMap[lModule->start] = lModule;

    while (Module32Next(hProcessSnapShot, &module_entry)) {
        LoadedModule *lModule = new LoadedModule(
            (ULONGLONG) module_entry.modBaseAddr, 
            (ULONGLONG) module_entry.modBaseAddr + module_entry.modBaseSize,
            module_entry.szExePath,
            process_id
            );
        modulesMap[lModule->start] = lModule;
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return modulesMap.size();
}

void peconv::ProcessModules::delete_mapping()
{
    std::map<ULONGLONG, LoadedModule*>::iterator itr = modulesMap.begin();
    for (; itr != modulesMap.end(); itr++ ) {
        const LoadedModule *module = itr->second;
        delete module;
    }
    this->modulesMap.clear();
}

const peconv::LoadedModule* peconv::ProcessModules::get_module_containing(ULONGLONG address)
{
    std::map<ULONGLONG, LoadedModule*>::iterator start_itr = modulesMap.begin();
    std::map<ULONGLONG, LoadedModule*>::iterator stop_itr = modulesMap.upper_bound(address);
    std::map<ULONGLONG, LoadedModule*>::iterator itr = start_itr;
    for (; itr != stop_itr; itr++ ) {
        const LoadedModule *module = itr->second;

        if (address >= module->start && address < module->end) {
            return module;
        }
    }
    return nullptr;
}

HMODULE peconv::get_module_containing(ULONGLONG address)
{
    ProcessModules modules(GetCurrentProcessId());
    modules.load_mapping();
    const LoadedModule* module = modules.get_module_containing(address);
    if (module == nullptr) {
        return nullptr;
    }
    return HMODULE(module->start);
}
