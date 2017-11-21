#include <stdio.h>

#include "test_loading.h"
#include "test_loading_imps.h"

int make_test(int test_id)
{
    switch (test_id) {
        case 1:  return tests::load_self();
        case 2: return tests::deploy_self();
    }
    return -1;
}

void print_banner()
{
    printf("---------------\n");
    printf("TESTS DEPLOYED!\n");
    printf("---------------\n");
}

int main(int argc, char *argv[])
{
    print_banner();
    if (argc < 2) {
        printf("Supply the test id!\n");
            system("pause");
        return 0;
    }
    
    int test_id = atoi(argv[1]);
    printf("Test ID: %d\n", test_id);
    int res = make_test(test_id);

    if (res == 0) {
        printf("[+] Test passed!\n");
    }
    system("pause");
    return res;
}
