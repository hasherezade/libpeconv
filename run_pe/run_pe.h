#pragma once

#include <windows.h>

/**
Perform the RunPE injection of the payload into the target.
*/
bool run_pe(char *payloadPath, char *targetPath);
