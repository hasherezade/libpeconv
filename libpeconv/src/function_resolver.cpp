#include "peconv/function_resolver.h"

#include "peconv/logger.h"
#include <cctype>

namespace util {
    std::string toLowercase(std::string str)
    {
        for (char& ch : str) {
            ch = std::tolower(static_cast<unsigned char>(ch));
        }
        return str;
    }
}; //namespace util

HMODULE peconv::default_func_resolver::load_library(LPCSTR lib_name)
{
    if (!lib_name) {
        return nullptr;
    }
    const std::string modName = util::toLowercase(lib_name);
    auto found = this->nameToModule.find(modName);
    if (found != this->nameToModule.end()) {
        return found->second;
    }
    const HMODULE mod = LoadLibraryA(lib_name);
    if (mod) {
        LOG_DEBUG("Loaded DLL: %s at %p.", lib_name, mod);
        this->nameToModule[modName] = mod;
    }
    return mod;
}

FARPROC peconv::default_func_resolver::resolve_func(LPCSTR lib_name, LPCSTR func_name)
{
    HMODULE libBasePtr = load_library(lib_name);
    if (libBasePtr == NULL) {
        LOG_ERROR("Could not load the library: %s.", lib_name);
        return NULL;
    }
    FARPROC hProc = GetProcAddress(libBasePtr, func_name);
    if (hProc == NULL) {
        ULONGLONG func_val = (ULONGLONG)func_name;
        //is only the first WORD filled?
        bool is_ord = (func_val & (0x0FFFF)) == func_val;
        if (is_ord) {
            LOG_ERROR("Could not load the function: %s.0x%llx.", lib_name, (unsigned long long)func_val);
        } else {
            LOG_ERROR("Could not load the function: %s.%s.", lib_name, func_name);
        }
        return NULL;
    }
    return hProc;
}
