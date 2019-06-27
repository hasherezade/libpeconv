#pragma once

#include <Windows.h>
#include <string>
#include <algorithm>
#include <set>

namespace peconv {

    /**
    Check if the pointer redirects to a forwarder - if so, return the length, otherwise return 0.
    */
    size_t forwarder_name_len(BYTE* fPtr); 

    /**
    get the DLL name without the extension
    */
    std::string get_dll_shortname(const std::string& str);

    /**
    Get the function name from the string in a format: DLL_name.function_name
    */
    std::string get_func_name(const std::string& str);

    /**
    Convert ordinal value to the ordinal string (in a format #<ordinal>)
    */
    std::string ordinal_to_string(DWORD func_ordinal);

    /**
    Check if the given string is in a format typical for storing ordinals (#<ordinal>)
    */
    bool is_ordinal_string(const std::string& str);

    /**
    Get the ordinal value from the ordinal string (in a format #<ordinal>)
    */
    DWORD ordinal_string_to_val(const std::string& str);

    /**
    Convert the function in a format: DLL_name.function_name into a normalized form (DLL name in lowercase).
    */
    std::string format_dll_func(const std::string& str);

    /**
    A class storing the information about the exported function.
    */
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

        // full info about the function: library, name, ordinal
        std::string toString() const;

        // short info: only function name or ordinal (if the name is missing)
        std::string nameToString() const;

        bool isValid() const
        {
            return (funcName != "" || funcOrdinal != -1);
        }
    };

}; //namespace peconv

