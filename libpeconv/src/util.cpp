#include "peconv/util.h"
#include <iostream>

namespace peconv {
    DWORD(WINAPI *g_GetProcessId)(IN HANDLE Process) = nullptr;

    HMODULE g_kernel32Hndl = nullptr;
    HMODULE g_ntdllHndl = nullptr;

    HMODULE get_kernel32_hndl()
    {
        if (g_kernel32Hndl == nullptr) {
            g_kernel32Hndl = LoadLibraryA("kernel32.dll");
        }
        return g_kernel32Hndl;
    }

    HMODULE get_ntdll_hndl()
    {
        if (g_ntdllHndl == nullptr) {
            g_ntdllHndl = LoadLibraryA("ntdll.dll");
        }
        return g_ntdllHndl;
    }
};

DWORD ntdll_get_process_id(HANDLE hProcess)
{
#if !defined PROCESSINFOCLASS
    typedef LONG PROCESSINFOCLASS;
#endif

    NTSTATUS(WINAPI *_ZwQueryInformationProcess)(
        IN       HANDLE ProcessHandle,
        IN       PROCESSINFOCLASS ProcessInformationClass,
        OUT      PVOID ProcessInformation,
        IN       ULONG ProcessInformationLength,
        OUT  PULONG ReturnLength
    ) = NULL;

    HINSTANCE hNtDll = peconv::get_ntdll_hndl();
    if (!hNtDll) {
        return 0;
    }

    FARPROC procPtr = GetProcAddress(hNtDll, "ZwQueryInformationProcess");
    if (!procPtr) {
        return 0;
    }

    _ZwQueryInformationProcess = (NTSTATUS(WINAPI *)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG)
     ) procPtr;

    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    if (_ZwQueryInformationProcess(hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) == S_OK) {
        const DWORD pid = static_cast<DWORD>(pbi.UniqueProcessId);
        return pid;
    }
    return 0;
}

DWORD peconv::get_process_id(HANDLE hProcess)
{
    if (!peconv::g_GetProcessId) {
        HMODULE kernelLib = peconv::get_kernel32_hndl();
        if (!kernelLib) return FALSE;

        FARPROC procPtr = GetProcAddress(kernelLib, "GetProcessId");
        if (!procPtr) return FALSE;

        peconv::g_GetProcessId = (DWORD(WINAPI *) (IN HANDLE))procPtr;
    }
    if (peconv::g_GetProcessId) {
        return peconv::g_GetProcessId(hProcess);
    }
    //could not retrieve Pid using GetProcessId, try using NTDLL:
    return ntdll_get_process_id(hProcess);
}

bool peconv::is_padding(const BYTE *cave_ptr, size_t cave_size, const BYTE padding)
{
    for (size_t i = 0; i < cave_size; i++) {
        if (cave_ptr[i] != padding) {
            return false;
        }
    }
    return true;
}

bool peconv::is_mem_accessible(LPCVOID areaStart, SIZE_T areaSize, DWORD dwAccessRights)
{
    if (!areaSize) return false; // zero-sized areas are not allowed

    const DWORD dwForbiddenArea = PAGE_GUARD | PAGE_NOACCESS;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    const size_t mbiSize = sizeof(MEMORY_BASIC_INFORMATION);

    SIZE_T sizeToCheck = areaSize;
    LPCVOID areaPtr = areaStart;

    while (sizeToCheck > 0) {
        //reset area
        memset(&mbi, 0, mbiSize);

        // query the next area
        if (VirtualQuery(areaPtr, &mbi, mbiSize) != mbiSize) {
            return false; // could not query the area, assume it is bad
        }
        // check the privileges
        bool isOk = (mbi.State & MEM_COMMIT) // memory allocated and
            && !(mbi.Protect & dwForbiddenArea) // access to page allowed and
            && (mbi.Protect & dwAccessRights); // the required rights
        if (!isOk) {
            return false; //invalid access
        }
        SIZE_T offset = (ULONG_PTR)areaPtr - (ULONG_PTR)mbi.BaseAddress;
        SIZE_T queriedSize = mbi.RegionSize - offset;
        if (queriedSize >= sizeToCheck) {
            return true; // is is fine
        }
        // move to the next region
        sizeToCheck -= queriedSize;
        areaPtr = LPCVOID((ULONG_PTR)areaPtr + queriedSize);
    }
    // by default assume it is inaccessible
    return false;
}

bool peconv::is_bad_read_ptr(LPCVOID areaStart, SIZE_T areaSize)
{
    const DWORD dwReadRights = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    bool isAccessible = peconv::is_mem_accessible(areaStart, areaSize, dwReadRights);
    if (isAccessible) {
        // the area has read access rights: not a bad read pointer
        return false;
    }
    return true;
}
