#pragma once

#include <windows.h>

/**
Perform the RunPE injection of the payload into the target.
*/
bool run_pe(IN LPCTSTR payloadPath, IN LPCTSTR targetPath, IN LPCTSTR cmdLine);

BOOL update_remote_entry_point(PROCESS_INFORMATION& pi, ULONGLONG entry_point_va, bool is32bit);
