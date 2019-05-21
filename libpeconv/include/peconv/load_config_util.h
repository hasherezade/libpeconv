#pragma once

#include <Windows.h>
#include "buffer_util.h"

#include "load_config_defs.h"

namespace peconv {

	typedef enum {
		LOAD_CONFIG_NONE = 0,
		LOAD_CONFIG_W7_VER = 7,
		LOAD_CONFIG_W8_VER = 8,
		LOAD_CONFIG_W10_VER = 10,
		LOAD_CONFIG_UNK_VER = -1
	} t_load_config_ver;

	BYTE* get_load_config_ptr(BYTE* buffer, size_t buf_size);

	t_load_config_ver get_load_config_version(BYTE* buffer, size_t buf_size, BYTE* ld_config_ptr);

}; // namespace peconv
