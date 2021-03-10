#pragma once

#include <windows.h>

/**
Perform the RunPE injection of the payload into the target.
*/
bool run_pe(IN const char *payloadPath, IN const char *targetPath, IN const char* cmdLine);
