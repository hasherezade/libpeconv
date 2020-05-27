#include <Windows.h>
#include <iostream>
#include "api.h"

int main()
{
    std::cout << "Test Case 5 started..." << std::endl;
    DWORD checks = test_checksum1();
    checks += test_checksum2();
    checks += test_checksum3();
    checks +=  test_checksum4();
    checks += test_checksum5();

    std::cout << "Test Case 5 finished, checks: " << std::hex << checks << std::endl;
    return checks;
}
