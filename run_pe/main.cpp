#include <stdio.h>
#include <peconv.h>
#include <tchar.h>
#include "run_pe.h"

LPCTSTR version = TEXT("0.1.7");

int _tmain(int argc, LPTSTR argv[])
{
    LPTSTR payload_path = NULL;
    LPTSTR target_path = NULL;

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

    run_pe(payload_path, target_path, trimmedCmdLine.c_str());

    system("pause");
    return 0;
}
