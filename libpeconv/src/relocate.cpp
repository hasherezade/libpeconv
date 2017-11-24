#include "relocate.h"

#include "pe_hdrs_helper.h"
#include <stdio.h>

using namespace peconv;

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;


bool apply_reloc_block(BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, ULONGLONG oldBase, ULONGLONG newBase, PVOID modulePtr, SIZE_T moduleSize, bool is64bit)
{
	BASE_RELOCATION_ENTRY* entry = block;
	SIZE_T i = 0;
	for (i = 0; i < entriesNum; i++) {
		DWORD offset = entry->Offset;
		DWORD type = entry->Type;
		if (entry == NULL || type == 0) {
			break;
		}
		if (type != RELOC_32BIT_FIELD && type != RELOC_64BIT_FIELD) {
			printf("[-] Not supported relocations format at %d: %d\n", (int) i, (int) type);
			return false;
		}
		DWORD reloc_field = page + offset;
		if (reloc_field >= moduleSize) {
			printf("[-] Malformed field: %lx\n", reloc_field);
			return false;
		}
		if (is64bit) {
			ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)modulePtr + reloc_field);
			ULONGLONG rva = (*relocateAddr) - oldBase;
			(*relocateAddr) = rva + newBase;
		}
		else {
			DWORD* relocateAddr = (DWORD*)((ULONG_PTR)modulePtr + reloc_field);
			ULONGLONG rva = (*relocateAddr) - oldBase;
			(*relocateAddr) = static_cast<DWORD>(rva + newBase);
		}
		entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
	}
	return true;
}

bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
{
	IMAGE_DATA_DIRECTORY* relocDir = get_pe_directory((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (relocDir == NULL) {
#ifdef _DEBUG
		printf("[!] WARNING: no relocation table found!\n");
#endif
		return false;
	}
	if (!validate_ptr(modulePtr, moduleSize, relocDir, sizeof(IMAGE_DATA_DIRECTORY))) {
		return false;
	}
	DWORD maxSize = relocDir->Size;
	DWORD relocAddr = relocDir->VirtualAddress;
	bool is64b = is64bit((BYTE*)modulePtr);

	IMAGE_BASE_RELOCATION* reloc = NULL;

	DWORD parsedSize = 0;
	while (parsedSize < maxSize) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR)modulePtr);
		if (!validate_ptr(modulePtr, moduleSize, reloc, sizeof(IMAGE_BASE_RELOCATION))) {
			printf("[-] Invalid address of relocations\n");
			return false;
		}
		parsedSize += reloc->SizeOfBlock;

		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
			break;
		}

		size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
		DWORD page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
		if (!validate_ptr(modulePtr, moduleSize, block, sizeof(BASE_RELOCATION_ENTRY))) {
			printf("[-] Invalid address of relocations block\n");
			return false;
		}
		if (apply_reloc_block(block, entriesNum, page, oldBase, newBase, modulePtr, moduleSize, is64b) == false) {
			return false;
		}
	}
	return (parsedSize != 0);
}

bool peconv::relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
{
    if (modulePtr == NULL) {
        return false;
    }
    if (oldBase == NULL) {
        oldBase = get_image_base(modulePtr);
    }
#ifdef _DEBUG
    printf("New Base: %llx\n", newBase);
    printf("Old Base: %llx\n", oldBase);
#endif
    if (newBase == oldBase) {
#ifdef _DEBUG
	    printf("Nothing to relocate! oldBase is the same as the newBase!\n");
#endif
		return true; //nothing to relocate
	}
	if (apply_relocations(modulePtr, moduleSize, newBase, oldBase)) {
		return true;
	}
#ifdef _DEBUG
	printf("Could not relocate the module!\n");
#endif
	return false;
}