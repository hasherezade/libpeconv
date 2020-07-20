#include "test_fix_dotnet.h"

#include <peconv.h>
#include "..\\libpeconv\src\fix_dot_net_ep.h"

namespace tests {

    bool test_finding_offset(BYTE *buf, const size_t buf_size, size_t pattern_offset, bool direction_start=true)
    {
        const BYTE pattern[] =  { 0xFF, 0x25, 0x00, 0x20, 0x40, 0x00 };
        const ULONGLONG img_base = 0x400000;
        const DWORD cor_exe_main_thunk = 0x2000;

        // reset buffer:
        memset(buf, 0, buf_size);

        if (!direction_start) {
            pattern_offset = (buf_size - sizeof(pattern)) - pattern_offset;
        }
        if (buf_size > sizeof(pattern) || (pattern_offset + sizeof(pattern)) > buf_size) {
            std::cerr << __FILE__ << " incorrect test data!" << std::endl;
            return false;
        }
        memcpy(buf + pattern_offset, pattern, sizeof(pattern));

        BYTE* found = search_jump(buf, buf_size, cor_exe_main_thunk, img_base);
        if (!found) {
            std::cout << "Not found!\n";
            return false;
        }
        size_t diff = found - buf;
        std::cout << "Fount at offset: " << std::hex << diff << "\n";
        if (diff == pattern_offset) {
            return true;
        }
        return false;
    }
};

int tests::check_finding_jumps()
{
    BYTE buf[0x100] = { 0 };

    bool is_ok = test_finding_offset(buf, sizeof(buf), 0, true);
    if (is_ok) {
		std::cout << "Test 1 passed!\n";
	} else {
		std::cout << "Test 1 failed!\n";
		return 1;
	}
	is_ok = test_finding_offset(buf, sizeof(buf), 0, false);
	if (is_ok) {
		std::cout << "Test 2 passed!\n";
	}
    else {
        std::cout << "Test 2 failed!\n";
        return 1;
    }

    is_ok = test_finding_offset(buf, sizeof(buf), 30, false);
    if (is_ok) {
        std::cout << "Test 3 passed!\n";
    }
    else {
        std::cout << "Test 2 failed!\n";
        return 1;
    }
    return 0;
}
