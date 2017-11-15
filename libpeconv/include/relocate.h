#pragma once
#include <Windows.h>
#include "pe_hdrs_helper.h"

#include <stdio.h>

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

bool has_relocations(BYTE *pe_buffer);

/** 
 Applies relocations on the PE in virtual format. Relocates it from the old base given to the new base given.
 */
bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase);

/** 
 Applies relocations on the PE in virtual format. Relocates it from the old base given to the new base given.
 If NULL was supplied as the old base, it assumes that the old base is the ImageBase given in the header.
 If applying relocations was not possible, it changes the ImageBase saved in the header to the newBase.
 */
bool relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase=NULL);