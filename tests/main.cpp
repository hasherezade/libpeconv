#include <stdio.h>

#include "test_loading.h"
#include "test_loading_imps.h"
#include "test_crackme_f4_3.h"
#include "test_hooking_imps.h"
#include "test_crackme_f4_6.h"
#include "test_load_ntdll.h"

int make_test(int test_id, char *test_arg)
{
    switch (test_id) {
        case 1:  return tests::load_self();
        case 2: return tests::deploy_self();
        case 3: return tests::brutforce_crackme_f4_3();
        case 4: 
            {
            peconv::export_based_resolver *exp_res = new peconv::export_based_resolver();
            int res = tests::deploy_self_ex((peconv::t_function_resolver*)exp_res);
            delete exp_res;
            return res;
            }
        case 5: return tests::hook_testcase(test_arg);
        case 6: return tests::decode_crackme_f4_6(test_arg);
        case 7: return tests::test_ntdll(NULL);
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

    char *test_arg = NULL; 
    if (argc > 2) {
        test_arg = argv[2];
    }
    int res = make_test(test_id, test_arg);

    if (res == 0) {
        printf("[+] Test passed!\n");
    }
    return res;
}
