#include <stdio.h>
#include "test_loading.h"


int make_test(int test_id)
{
    switch (test_id) {
        case 1:  return tests::load_self();
    }
    return -1;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Supply the test id!\n");
        return 0;
    }
    int test_id = atoi(argv[1]);
    int res = make_test(test_id);

    if (res == 0) {
        printf("[+] Test passed - the unmapped module is the same as the original!\n");
    }
    return res;
}
