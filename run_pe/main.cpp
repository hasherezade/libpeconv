#include <stdio.h>
#include <peconv.h>
#include <tchar.h>
#include "run_pe.h"

LPCTSTR version = TEXT("0.2");

bool g_PatchRequired = false;

bool isWindows1124H2OrLater()
{
    NTSYSAPI NTSTATUS RtlGetVersion( PRTL_OSVERSIONINFOW lpVersionInformation );

    RTL_OSVERSIONINFOW osVersionInfo = { 0 };
    osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) return false; // should never happen

    auto _RtlGetVersion = reinterpret_cast<decltype(&RtlGetVersion)>(GetProcAddress(hNtdll, "RtlGetVersion"));
    NTSTATUS status = _RtlGetVersion(
       &osVersionInfo
    );
    if (status != S_OK) {
        std::cerr << "Failed to retrieve OS version information." << std::endl;
        return false;
    }
    // Check major version and build number for Windows 11
    if (osVersionInfo.dwMajorVersion > 10 ||
        (osVersionInfo.dwMajorVersion == 10 && osVersionInfo.dwBuildNumber >= 26100)) {
        return true;
    }
    return false;
}

int _tmain(int argc, LPTSTR argv[])
{
    LPTSTR payload_path = NULL;
    LPTSTR target_path = NULL;
    if (isWindows1124H2OrLater()) {
        std::cout << "WARNING: Executing RunPE on Windows11 24H2 or above requires patching NTDLL.ZwQueryVirtualMemory\n";
        g_PatchRequired = true;
    }
    if (argc < 3) {
        std::tcout << TEXT("[ run_pe v") << version << TEXT(" ]\n")
            << TEXT("Args: <payload_path> <target_path>\n");
        system("pause");
        return -1;
    }

    payload_path = argv[1];
    target_path = argv[2];

    std::tstring cmdLine = GetCommandLine();
    size_t found = cmdLine.find(target_path);

    // cut out the parameters that are dedicated to the run_pe app only
    std::tstring trimmedCmdLine = cmdLine.substr(found, cmdLine.length());
    
    std::tcout << TEXT("Payload: ") << payload_path << TEXT("\n");
    std::tcout << TEXT("Target: ") << target_path << TEXT("\n");

    bool isOk = run_pe(payload_path, target_path, trimmedCmdLine.c_str());
    if (!isOk) {
        std::cerr << "Failed!\n";
    }
    else {
        std::cout << "Done!\n";
    }
    return isOk ? 0 : (-1);
}
