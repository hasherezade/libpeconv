#include <stdio.h>
#include <windows.h>

#include "test_loading.h"
#include "test_loading_imps.h"
#include "test_crackme_f4_3.h"
#include "test_hooking_imps.h"
#include "test_crackme_f4_6.h"
#include "test_load_ntdll.h"
#include "test_replacing_func.h"
#include "test_delayed_imps.h"
#include "test_imp_list.h"
#include "test_hooking_local.h"
#include "test_peb_lookup.h"
#include "test_imports_mix.h"
#include "test_found_base.h"
#include "test_fix_dotnet.h"

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
        case 7: return tests::test_ntdll(NULL); //manual test
        case 8: return tests::replace_func_testcase(test_arg);
        case 9: return tests::replace_delayed_imps(test_arg);
        case 10: return tests::imp_list(test_arg); //manual test
        case 11: return tests::hook_self_local();
        case 12: return tests::check_modules();
        case 13: return tests::imports_mix(test_arg);
        case 14: return tests::load_and_check_base(test_arg);
		case 15: return tests::check_finding_jumps();
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
