#pragma once

#include <Windows.h>
#include <stdio.h>

#include "ntddk.h"

// Wrapper for the fuction: CreateProcessA. Creates a suspended process
bool create_suspended_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi);

// Wrapper for ReadProcessMemory. Zeroes the output buffer. Prints info about the error.
bool read_remote_mem(HANDLE hProcess, ULONGLONG remote_addr, OUT void* buffer, const size_t buffer_size);

bool run_pe(char *payloadPath, char *targetPath);