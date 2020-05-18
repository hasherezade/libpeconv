#include "peconv/exported_func.h"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace peconv;

std::string peconv::get_dll_shortname(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of('.');
    if (ext >= len) return "";

    std::string name = str.substr(found+1, ext - (found+1));
    std::transform(name.begin(), name.end(), name.begin(), tolower);
    return name;
}

size_t peconv::forwarder_name_len(BYTE* fPtr)
{
    // names can be also mangled, i.e. MSVCRT.??0__non_rtti_object@std@@QAE@ABV01@@Z
    bool has_dot = false;
    size_t len = 0;
    while ((*fPtr >= 'a' && *fPtr <= 'z')
            || (*fPtr >= 'A' && *fPtr <= 'Z')
            || (*fPtr >= '0' && *fPtr <= '9')
            || (*fPtr == '.')
            || (*fPtr == '_')
            || (*fPtr == '#') 
            || (*fPtr == '@')
            || (*fPtr == '?')
            || (*fPtr == '-'))
    {
        if (*fPtr == '.') has_dot = true;
        len++;
        fPtr++;
    }
    if (*fPtr == '\0') {
        if (!has_dot) {
            return 0; //this is not a valid forwarder
        }
        return len;
    }
    return 0;
}

std::string peconv::get_func_name(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(ext+1, len - (ext+1));
    return name;
}

std::string peconv::ordinal_to_string(DWORD func_ordinal)
{
    std::stringstream stream;
    stream << "#";
    stream << std::dec << func_ordinal;
    return stream.str();
}

bool peconv::is_ordinal_string(const std::string& func_name_str)
{
    if (func_name_str.length() < 2) return false;
    return (func_name_str[0] == '#');
}

DWORD peconv::ordinal_string_to_val(const std::string& func_name_str)
{
    if (!is_ordinal_string(func_name_str)) return 0;
    const char* func_name = func_name_str.c_str();
    return atoi(func_name + 1);
}

std::string peconv::format_dll_func(const std::string& str)
{
    std::string dllName = get_dll_shortname(str);
    std::string funcName = get_func_name(str);
    if (dllName.length() == 0 || funcName.length() == 0) {
        return "";
    }
    std::transform(dllName.begin(), dllName.end(), dllName.begin(), tolower);
    return dllName + "." + funcName;
}

ExportedFunc::ExportedFunc(std::string libName, std::string funcName, DWORD funcOrdinal)
{
    this->libName = ExportedFunc::formatName(libName);
    this->funcName = funcName;
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = false;
}

ExportedFunc::ExportedFunc(std::string libName, DWORD funcOrdinal)
{
    this->libName = ExportedFunc::formatName(libName);
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = true;
}

ExportedFunc::ExportedFunc(const ExportedFunc& other)
{
    this->libName = other.libName;
    this->funcName = other.funcName;
    this->funcOrdinal = other.funcOrdinal;
    this->isByOrdinal = other.isByOrdinal;
}

ExportedFunc::ExportedFunc(const std::string &forwarderName)
{
    this->libName = get_dll_shortname(forwarderName);
    std::string func_name_str =  get_func_name(forwarderName);
    if (func_name_str.length() < 2) {
        this->funcOrdinal = -1;
        this->funcName = "";
        this->isByOrdinal = false;
#ifdef _DEBUG
        std::cerr << "Invalid function data" << std::endl;
#endif
        return;
    }
    if (is_ordinal_string(func_name_str)) {
        // it is an ordinal in a string form, i.e.: "COMBASE.#110"
        this->funcOrdinal = peconv::ordinal_string_to_val(func_name_str);
        this->isByOrdinal = true;
        this->funcName = "";
        //std::cout << "[O] Adding forwarded func: " << forwarderName << " parsed: " << this->toString() << std::endl;
    } else {
        this->funcName = func_name_str;
        this->isByOrdinal = false;
        this->funcOrdinal = 0;
        //std::cout << "[N] Adding forwarded func:" << this->toString() << std::endl;
    }
}

std::string ExportedFunc::formatName(std::string name)
{
    if (name.length() == 0 || name.length() == 0) {
        return "";
    }
    std::transform(name.begin(), name.end(), name.begin(), tolower);
    return name;
}

std::string ExportedFunc::toString() const
{
    if (!isValid()) {
        return "[Invalid func]";
    }
    std::stringstream stream;
    stream << this->libName;
    stream << ".";
    if (!this->isByOrdinal) {
        stream << this->funcName;
        stream << " ";
    }
    stream << ordinal_to_string(this->funcOrdinal);
    return stream.str();
}

std::string ExportedFunc::nameToString() const
{
    if (!isValid()) {
        return "";
    }
    if (this->isByOrdinal) {
        return ordinal_to_string(this->funcOrdinal);
    }
    return this->funcName;
}
