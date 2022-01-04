#pragma once
#include <windows.h>

#define CONN_BUF_SIZE 4

bool listen_for_connect(char buf[CONN_BUF_SIZE], int port);
