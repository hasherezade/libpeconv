#include <stdio.h>

#include "test_loading.h"
#include "test_loading_imps.h"
#include "test_crackme_f4_3.h"

int make_test(int test_id)
{
    switch (test_id) {
        case 1:  return tests::load_self();
        case 2: return tests::deploy_self();
        case 3: return tests::brutforce_crackme_f4_3();
        case 4: return tests::deploy_self_ex(peconv::resolve_with_exports);
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
        return 0;
    }
    
    int test_id = atoi(argv[1]);
    printf("Test ID: %d\n", test_id);
    int res = make_test(test_id);

    if (res == 0) {
        printf("[+] Test passed!\n");
    }
    return res;
}
