#pragma once

#include <Windows.h>
#include <string>
#include <algorithm>
#include <set>

namespace peconv {

    // check if the pointer redirects to a forwarder. if so, return the length
    size_t forwarder_name_len(BYTE* fPtr); 

    // get the DLL name without the extension
    std::string get_dll_name(const std::string& str);

    std::string get_func_name(const std::string& str);
    std::string ordinal_to_string(DWORD func_ordinal);
    bool is_ordinal_string(const std::string& str);
    DWORD ordinal_string_to_val(const std::string& str);

    std::string format_dll_func(const std::string& str);

    class ExportedFunc
    {
    public:
        static std::string formatName(std::string name);

        std::string libName;
        std::string funcName;
        DWORD funcOrdinal;
        bool isByOrdinal;

        ExportedFunc(const ExportedFunc& other);
        ExportedFunc(std::string libName, std::string funcName, DWORD funcOrdinal);
        ExportedFunc(std::string libName, DWORD funcOrdinal);
        ExportedFunc(const std::string &forwarderName);

        bool operator < (const ExportedFunc& other) const
        {
            int cmp = libName.compare(other.libName);
            if (cmp != 0) {
                return cmp < 0;
            }
            const size_t thisNameLen = this->funcName.length();
            const size_t otherNameLen = other.funcName.length();
            if (thisNameLen == 0 || otherNameLen == 0) {
                return this->funcOrdinal < other.funcOrdinal;
            }
            if (thisNameLen != otherNameLen) {
                return thisNameLen < otherNameLen;
            }
            cmp = funcName.compare(other.funcName);
            return cmp < 0;
        }

        std::string ExportedFunc::toString() const;
    };

}; //namespace peconv

