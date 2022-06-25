#pragma once

#include <Windows.h>

char g_Pass[MAX_PATH] = { 0 };
volatile HANDLE g_pass_mutex = nullptr;
