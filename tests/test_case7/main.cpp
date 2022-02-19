#include <windows.h>
#include <iostream>

void make_exception1()
{
    std::cout << __FUNCTION__ << ": Throwing exception:" << std::endl;
    __try {
        RaiseException(STATUS_BREAKPOINT, 0, 0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "Exception handled: STATUS_BREAKPOINT" << std::endl;
    }
}

void make_exception2()
{
    std::cout << __FUNCTION__ << ": Throwing exception:" << std::endl;
    __try {
        RaiseException(STATUS_INTEGER_DIVIDE_BY_ZERO, 0, 0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "Exception handled: STATUS_INTEGER_DIVIDE_BY_ZERO"  << std::endl;
    }
}


int main()
{
    make_exception1();
    make_exception2();
    return 0;
}
