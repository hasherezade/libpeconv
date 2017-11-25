#include <stdio.h>
#include <Windows.h>

#include "test_crackme_f4_3.h"

#include "resource_helper.h"
#include "resource.h"

#include "peconv.h"

namespace test3 {
    BYTE *g_Buffer = NULL;
    const size_t g_BufferLen = 0x79;

    BYTE g_Buffer2[g_BufferLen] = { 0 };

    WORD (*calc_checksum) (BYTE *decoded_buffer, size_t buf_size) = NULL;

    bool test_val(BYTE xor_val)
    {
        for (size_t i = 0; i < g_BufferLen; i++) {
            BYTE val = g_Buffer[i];
            g_Buffer2[i] = (xor_val ^ val) + 0x22;
        }
        WORD checksum = calc_checksum(g_Buffer2, g_BufferLen);
        if (checksum == 0xfb5e) {
            return true;
        }
        return false;
    }

    BYTE brutforce()
    {
        BYTE xor_val = 0;
        do {
          xor_val++;
        } while (!test_val(xor_val));
        return xor_val;
    }
};

//---

int tests::brutforce_crackme_f4_3()
{
#ifdef _WIN64
    printf("Compile the loader as 32bit!\n");
    return 0;
#endif
    BYTE* loaded_pe = NULL;
    size_t v_size = 0;

    { //scope1
        size_t raw_size = 0;
        BYTE *raw_crackme = load_resource_data(raw_size, CRACKME_F4_3_32);
        if (!raw_crackme) {
            return -1;
        }
        loaded_pe = peconv::load_pe_module(raw_crackme, raw_size, v_size, true, false);
        if (!loaded_pe) {
            free_resource_data(raw_crackme, raw_size);
            return -1;
        }
        free_resource_data(raw_crackme, raw_size);
    }//!scope1

    test3::g_Buffer = (BYTE*) (0x107C + (ULONGLONG) loaded_pe);

    ULONGLONG func_offset = 0x11e6 + (ULONGLONG) loaded_pe;
    test3::calc_checksum =  ( WORD (*) (BYTE *, size_t ) ) func_offset;

    BYTE found = test3::brutforce();
    printf("Found: %x\n", found);
    int res = -1;
    if (found == 0xa2) {
        res = 0;
    }
    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}

int tests::deploy_crackme_f4_3()
{
#ifdef _WIN64
    printf("Compile the loader as 32bit!\n");
    return 0;
#endif
    BYTE* loaded_pe = NULL;
    size_t v_size = 0;

    { //scope1
        size_t raw_size = 0;
        BYTE *raw_crackme = load_resource_data(raw_size, CRACKME_F4_3_32);
        if (!raw_crackme) {
            return -1;
        }
        loaded_pe = peconv::load_pe_executable(raw_crackme, raw_size, v_size);
        if (!loaded_pe) {
            free_resource_data(raw_crackme, raw_size);
            return -1;
        }
        free_resource_data(raw_crackme, raw_size);
    }//!scope1

    test3::g_Buffer = (BYTE*) (0x107C + (ULONGLONG) loaded_pe);

    ULONGLONG func_offset = 0x11e6 + (ULONGLONG) loaded_pe;
    test3::calc_checksum =  ( WORD (*) (BYTE *, size_t ) ) func_offset;

    BYTE found = test3::brutforce();
    printf("Found: %x\n", found);
    int res = -1;
    if (found != 0xa2) {
        peconv::free_pe_buffer(loaded_pe, v_size);
        return -1;
    }
    ULONGLONG ep_va = peconv::get_entry_point_rva(loaded_pe) + (ULONGLONG) loaded_pe;
    printf("Press any key to go to function's entry point\n");
    system("pause");
    //make pointer to the entry function:
    int (*loaded_pe_entry)(void) = (int (*)(void)) ep_va;
    res = loaded_pe_entry();
    printf("Finished: %d\n", res);

    peconv::free_pe_buffer(loaded_pe, v_size);
    return 0;
}
