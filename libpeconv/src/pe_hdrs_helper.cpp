#include "peconv/pe_hdrs_helper.h"

using namespace peconv;

BYTE* peconv::get_nt_hrds(const BYTE *pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS32 *inh = (IMAGE_NT_HEADERS32 *)(pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return (BYTE*)inh;
}

IMAGE_NT_HEADERS32* peconv::get_nt_hrds32(const BYTE *payload)
{
	if (payload == NULL) return NULL;

	BYTE *ptr = get_nt_hrds(payload);
	if (ptr == NULL) return NULL;

	bool is64b = is64bit(payload);
	if (!is64b) {
		return (IMAGE_NT_HEADERS32*)ptr;
	}
	return NULL;
}

IMAGE_NT_HEADERS64* peconv::get_nt_hrds64(const BYTE *payload)
{
	if (payload == NULL) return NULL;

	BYTE *ptr = get_nt_hrds(payload);
	if (ptr == NULL) return NULL;

	bool is64b = is64bit(payload);
	if (is64b) {
		return (IMAGE_NT_HEADERS64*)ptr;
	}
	return NULL;
}

size_t peconv::get_image_size(const BYTE *payload)
{
	if (get_nt_hrds(payload) == NULL) {
		return 0;
	}
	DWORD image_size = 0;
	if (is64bit(payload)) {
		IMAGE_NT_HEADERS64* nt64 = get_nt_hrds64(payload);
		image_size = nt64->OptionalHeader.SizeOfImage;
	} else {
		IMAGE_NT_HEADERS32* nt32 = get_nt_hrds32(payload);
		image_size = nt32->OptionalHeader.SizeOfImage;
	}
	return image_size;
}

WORD peconv::get_pe_architecture(const BYTE *pe_buffer)
{
    void *ptr = get_nt_hrds(pe_buffer);
    if (ptr == NULL) return 0;

    IMAGE_NT_HEADERS32 *inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    return inh->FileHeader.Machine;
}

bool peconv::is64bit(const BYTE *pe_buffer)
{
	WORD arch = get_pe_architecture(pe_buffer);
	if (arch == IMAGE_FILE_MACHINE_AMD64) {
		return true;
	}
	return false;
}

IMAGE_DATA_DIRECTORY* peconv::get_directory_entry(const BYTE *pe_buffer, DWORD dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = get_nt_hrds((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;
	if (is64bit((BYTE*)pe_buffer)) {
		IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
		peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
	}
	else {
		IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
		peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
	}
	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

ULONGLONG peconv::get_image_base(const BYTE *pe_buffer)
{
	bool is64b = is64bit(pe_buffer);
	//update image base in the written content:
	BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
	if (payload_nt_hdr == NULL) {
		return 0;
	}
	ULONGLONG img_base = 0;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		img_base = payload_nt_hdr64->OptionalHeader.ImageBase;
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		img_base = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.ImageBase);
	}
	return img_base;
}

DWORD peconv::get_entry_point_rva(const BYTE *pe_buffer)
{
	bool is64b = is64bit(pe_buffer);
	//update image base in the written content:
	BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
	if (payload_nt_hdr == NULL) {
		return 0;
	}
	DWORD img_base = 0;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		img_base = payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint;
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		img_base = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint);
	}
	return img_base;
}

DWORD peconv::get_hdrs_size(const BYTE *pe_buffer)
{
	bool is64b = is64bit(pe_buffer);
	//update image base in the written content:
	BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
	if (payload_nt_hdr == NULL) {
		return 0;
	}
	DWORD hdrs_size = 0;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		hdrs_size = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		hdrs_size = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
	}
	return hdrs_size;
}

bool peconv::update_image_base(BYTE* payload, ULONGLONG destImageBase)
{
    bool is64b = is64bit(payload);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.ImageBase = (ULONGLONG)destImageBase;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.ImageBase = (DWORD)destImageBase;
    }
    return true;
}

size_t peconv::get_sections_count(const BYTE* payload, const size_t buffer_size)
{
	if (payload == NULL) return 0;

	bool is64b = is64bit(payload);
	BYTE* payload_nt_hdr = get_nt_hrds(payload);
	if (payload_nt_hdr == NULL) {
		return 0;
	}

	IMAGE_FILE_HEADER *fileHdr = NULL;
	DWORD hdrsSize = 0;
	LPVOID secptr = NULL;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr64->FileHeader);
		hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
		secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
	} else {
		 IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr32->FileHeader);
		hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
		secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
	}
	return fileHdr->NumberOfSections;
}

PIMAGE_SECTION_HEADER peconv::get_section_hdr(const BYTE* payload, const size_t buffer_size, size_t section_num)
{
	if (payload == NULL) return NULL;

	bool is64b = is64bit(payload);
	BYTE* payload_nt_hdr = get_nt_hrds(payload);
	if (payload_nt_hdr == NULL) {
		return NULL;
	}

	IMAGE_FILE_HEADER *fileHdr = NULL;
	DWORD hdrsSize = 0;
	LPVOID secptr = NULL;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr64->FileHeader);
		hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
		secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr32->FileHeader);
		hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
		secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
	}
	if (section_num >= fileHdr->NumberOfSections) {
		return NULL;
	}
	PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)(
		(ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * section_num)
		);

	//validate pointer
	if (!validate_ptr((const LPVOID) payload, buffer_size, (const LPVOID) next_sec, sizeof(IMAGE_SECTION_HEADER))) {
		return NULL;
	}
	return next_sec;
}

bool peconv::is_module_dll(const BYTE* payload)
{
	if (payload == NULL) return false;

	bool is64b = is64bit(payload);
	BYTE* payload_nt_hdr = get_nt_hrds(payload);
	if (payload_nt_hdr == NULL) {
		return false;
	}
	IMAGE_FILE_HEADER *fileHdr = NULL;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr64->FileHeader);
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr32->FileHeader);
	}
	DWORD flag = fileHdr->Characteristics & 0x2000;
	return (flag != 0);
}

bool peconv::set_subsystem(BYTE* payload, WORD subsystem)
{
	if (payload == NULL) return false;

	bool is64b = is64bit(payload);
	BYTE* payload_nt_hdr = get_nt_hrds(payload);
	if (payload_nt_hdr == NULL) {
		return false;
	}
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		payload_nt_hdr64->OptionalHeader.Subsystem = subsystem;
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		payload_nt_hdr32->OptionalHeader.Subsystem = subsystem;
	}
	return true;
}

WORD peconv::get_subsystem(const BYTE* payload)
{
	if (payload == NULL) return false;

	bool is64b = is64bit(payload);
	BYTE* payload_nt_hdr = get_nt_hrds(payload);
	if (payload_nt_hdr == NULL) {
		return false;
	}
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		return payload_nt_hdr64->OptionalHeader.Subsystem;
	} else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		return payload_nt_hdr32->OptionalHeader.Subsystem;
	}
}

bool peconv::has_relocations(BYTE *pe_buffer)
{
	IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (relocDir == NULL) {
		return false;
	}
	return true;
}

template <typename IMAGE_TYPE_DIRECTORY>
IMAGE_TYPE_DIRECTORY* peconv::get_type_directory(HMODULE modulePtr, DWORD dir_id)
{
    IMAGE_DATA_DIRECTORY *my_dir = peconv::get_directory_entry((const BYTE*) modulePtr, dir_id);
    if (my_dir == NULL) return NULL;

    DWORD dir_addr = my_dir->VirtualAddress;
    if (dir_addr == 0) return NULL;

    return (IMAGE_TYPE_DIRECTORY*)(dir_addr + (ULONG_PTR) modulePtr);
}

IMAGE_EXPORT_DIRECTORY* peconv::get_export_directory(HMODULE modulePtr)
{
    return get_type_directory<IMAGE_EXPORT_DIRECTORY>(modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
}