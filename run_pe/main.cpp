#include <stdio.h>
#include "peconv.h"

#include "run_pe.h"

int main(int argc, char *argv[])
{
    char* version = "0.1.6";
    char* payload_path = NULL;

    char *target_path = NULL;

    if (argc < 2) {
        printf("[ run_pe v%s ]\n\n", version);
        printf("Args: <payload_path> [*target_path]\n");
        printf("* - optional\n");
        system("pause");
        return -1;
    }
    payload_path = argv[1];
    if (argc > 2) {
        target_path = argv[2];
    }

    printf("Payload: %s\n", payload_path );

    std::string cmdLine = GetCommandLineA();
    size_t found = cmdLine.find(target_path);

    //cut the cmdLine just before the target_path
    std::string trimmedCmdLine = cmdLine.substr(found, cmdLine.length());

    run_pe(payload_path, target_path, trimmedCmdLine.c_str());

    system("pause");
    return 0;
}
