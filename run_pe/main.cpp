#include <stdio.h>
#include "peconv.h"

#include "run_pe.h"

bool get_calc_path(LPSTR lpOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStringsA("%SystemRoot%\\system32\\calc.exe", lpOutPath, szOutPath);
    printf("%s\n", lpOutPath );
    return true;
}

int main(int argc, char *argv[])
{
    char* version = "0.1";
    char* payload_path = NULL;

    char calc_path[MAX_PATH] = { 0 };
    get_calc_path(calc_path, MAX_PATH);
    char *target_path = calc_path;

    ULONGLONG loadBase = 0;
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
    printf("Target: %s\n", target_path );
    printf("Payload: %s\n", payload_path );
    run_pe(payload_path, target_path);

    system("pause");
    return 0;
}
