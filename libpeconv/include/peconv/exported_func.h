#pragma once

#include <Windows.h>
#include <string>
#include <algorithm>
#include <set>

namespace peconv {

    size_t forwarderNameLen(BYTE* fPtr); 

    std::string getDllName(const std::string& str);

    std::string getFuncName(const std::string& str);

    std::string formatDllFunc(const std::string& str);

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

