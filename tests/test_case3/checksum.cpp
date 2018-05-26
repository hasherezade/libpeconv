#include "checksum.h"

inline DWORD rotl32a(DWORD x, DWORD n)
{
    return (x << n) | (x >> (32 - n));
}

inline char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        c = c - 'A' + 'a';
    }
    return c;
}

DWORD calc_checksum(BYTE *str, size_t buf_size, bool enable_tolower)
{
    if (str == NULL) return 0;

    DWORD checksum = 0;
    for (size_t i = 0; i < buf_size; i++) {
        checksum = rotl32a(checksum, 7);
        char c = str[i];
        if (enable_tolower) {
            c = to_lower(c);
        }
        checksum ^= c;
    }
    return checksum;
}

DWORD calc_checksum(char *str, bool enable_tolower)
{
    return calc_checksum((BYTE*)str, strlen(str), enable_tolower);
}
