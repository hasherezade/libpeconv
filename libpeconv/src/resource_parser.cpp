#include "peconv/resource_parser.h"
#include "peconv/pe_hdrs_helper.h"

#ifdef _DEBUG
#include <iostream>
#endif

bool parse_resource_dir(BYTE* modulePtr, const size_t moduleSize,
    IMAGE_RESOURCE_DIRECTORY_ENTRY *root_dir, 
    const IMAGE_RESOURCE_DIRECTORY *upper_dir, 
    IMAGE_RESOURCE_DIRECTORY* curr_dir,
    peconv::t_on_res_entry_found on_entry);

bool parse_resource_entry(BYTE* modulePtr, const size_t moduleSize, 
    IMAGE_RESOURCE_DIRECTORY_ENTRY *root_dir,
    const IMAGE_RESOURCE_DIRECTORY *upper_dir, 
    IMAGE_RESOURCE_DIRECTORY_ENTRY* entry,
    peconv::t_on_res_entry_found on_entry)
{
    if (!entry->DataIsDirectory) {
#ifdef _DEBUG
        std::cout << "Entry is NOT a directory\n";
#endif
        DWORD offset = entry->OffsetToData;
#ifdef _DEBUG
        std::cout << "Offset: " << offset << std::endl;
#endif
        IMAGE_RESOURCE_DATA_ENTRY *data_entry = (IMAGE_RESOURCE_DATA_ENTRY*)(offset + (ULONGLONG)upper_dir);
        if (!peconv::validate_ptr(modulePtr, moduleSize, data_entry, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
            return false;
        }
#ifdef _DEBUG
        std::cout << "Data Offset: " << data_entry->OffsetToData << " : " << data_entry->Size << std::endl;
#endif
        BYTE* data_ptr = (BYTE*)((ULONGLONG)modulePtr + data_entry->OffsetToData);
        if (!peconv::validate_ptr(modulePtr, moduleSize, data_ptr, data_entry->Size)) {
            return false;
        }
        on_entry(modulePtr, moduleSize, root_dir, data_entry);
        return true;
    }
#ifdef _DEBUG
    std::cout << "Entry is a directory\n";
#endif
    //else: it is a next level directory
    DWORD offset = entry->OffsetToDirectory;
#ifdef _DEBUG
    std::cout << "Offset: " << offset << std::endl;
#endif
    IMAGE_RESOURCE_DIRECTORY *next_dir = (IMAGE_RESOURCE_DIRECTORY*)(offset + (ULONGLONG)upper_dir);
    if (!peconv::validate_ptr(modulePtr, moduleSize, next_dir, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
        return false;
    }
    return parse_resource_dir(modulePtr, moduleSize, root_dir, upper_dir, next_dir, on_entry);
}

bool parse_resource_dir(BYTE* modulePtr, const size_t moduleSize,
    IMAGE_RESOURCE_DIRECTORY_ENTRY *root_dir, 
    const IMAGE_RESOURCE_DIRECTORY *upper_dir,
    IMAGE_RESOURCE_DIRECTORY* curr_dir,
    peconv::t_on_res_entry_found on_entry)
{
    size_t total_entries = curr_dir->NumberOfIdEntries + curr_dir->NumberOfNamedEntries;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* first_entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((ULONGLONG)&curr_dir->NumberOfIdEntries + sizeof(WORD));
    for (size_t i = 0; i < total_entries; i++) {
        IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = &first_entry[i];
#ifdef _DEBUG
        std::cout << "Entry:" << std::hex << i << " ; " << "Id: " << entry->Id << " ; dataOffset:" << entry->OffsetToData << "\n";
#endif
        if (root_dir == nullptr) {
            root_dir = entry;
        }
        parse_resource_entry(modulePtr, moduleSize, root_dir, upper_dir, entry, on_entry);
    }
    return true;
}

bool peconv::parse_resources(BYTE* modulePtr, const size_t modulSize, t_on_res_entry_found on_entry)
{
    //const size_t module_size = peconv::get_image_size(modulePtr, modulSize);
    IMAGE_DATA_DIRECTORY *dir = peconv::get_directory_entry(modulePtr, modulSize, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if (!dir || dir->VirtualAddress == 0 || dir->Size == 0) {
        return false;
    }
    IMAGE_RESOURCE_DIRECTORY *res_dir = (IMAGE_RESOURCE_DIRECTORY*)(dir->VirtualAddress + (ULONGLONG)modulePtr);
    if (!peconv::validate_ptr(modulePtr, modulSize, res_dir, sizeof(IMAGE_DEBUG_DIRECTORY))) {
        return false;
    }
    return parse_resource_dir(modulePtr, modulSize, nullptr, res_dir, res_dir, on_entry);
}
