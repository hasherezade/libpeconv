#include "file_helper.h"

BYTE* load_file(char *filename, OUT size_t &r_size)
{
    HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        printf("Could not open file!");
#endif
        return NULL;
    }
    HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
#ifdef _DEBUG
        printf("Could not create mapping!");
#endif
        CloseHandle(file);
        return NULL;
    }
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (dllRawData == NULL) {
#ifdef _DEBUG
        printf("Could not map view of file");
#endif
        CloseHandle(mapping);
        CloseHandle(file);
        return NULL;
    }
    r_size = GetFileSize(file, 0);
    BYTE* localCopyAddress = (BYTE*) VirtualAlloc(NULL, r_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return NULL;
    }
    memcpy(localCopyAddress, dllRawData, r_size);
    UnmapViewOfFile(dllRawData);
    CloseHandle(mapping);
    CloseHandle(file);
    return localCopyAddress;
}

void free_file(BYTE* buffer, size_t buffer_size)
{
    VirtualFree(buffer, buffer_size, MEM_DECOMMIT);
}