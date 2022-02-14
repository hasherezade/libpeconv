#pragma once

#include <windows.h>

/**
Perform the RunPE injection of the payload into the target.
*/
bool run_pe(IN const char *payloadPath, IN const char *targetPath, IN const char* cmdLine);

BOOL update_remote_entry_point(PROCESS_INFORMATION& pi, ULONGLONG entry_point_va, bool is32bit);
