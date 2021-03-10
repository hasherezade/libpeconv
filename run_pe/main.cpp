#include <stdio.h>
#include <peconv.h>

#include "run_pe.h"

const char* version = "0.1.7";

int main(int argc, char *argv[])
{
    char* payload_path = NULL;
    char *target_path = NULL;

    if (argc < 3) {
        std::cout << "[ run_pe v" << version << " ]\n"
            << "Args: <payload_path> <target_path>\n";
        system("pause");
        return -1;
    }

    payload_path = argv[1];
    target_path = argv[2];

    std::string cmdLine = GetCommandLineA();
    size_t found = cmdLine.find(target_path);

    // cut out the parameters that are dedicated to the run_pe app only
    std::string trimmedCmdLine = cmdLine.substr(found, cmdLine.length());
    
    std::cout << "Payload: " << payload_path << "\n";
    std::cout << "Target: " << target_path << "\n";

    run_pe(payload_path, target_path, trimmedCmdLine.c_str());

    system("pause");
    return 0;
}
