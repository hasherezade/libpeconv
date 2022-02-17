# libPeConv
[![Build status](https://ci.appveyor.com/api/projects/status/pqo6ob148pf5b352?svg=true)](https://ci.appveyor.com/project/hasherezade/libpeconv)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/55911b033cf145d38d6e38a0c005b686)](https://app.codacy.com/gh/hasherezade/libpeconv/dashboard?branch=master)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hasherezade/libpeconv)](https://github.com/hasherezade/libpeconv/commits)
[![Last Commit](https://img.shields.io/github/last-commit/hasherezade/libpeconv/master)](https://github.com/hasherezade/libpeconv/commits)

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Platform Badge](https://img.shields.io/badge/Windows-0078D6?logo=windows)](https://github.com/hasherezade/libpeconv)

*A library to load and manipulate PE files.*

### Objectives

The goal of libPEConv was to create a "swiss army knife" for custom loading of PE files. It gathers various helper functions that you can quickly integrate in your own loader. For example: remapping sections, applying relocations, loading imports, parsing resources. 

Not only it allows for loading PE files, but also for customizing of some steps, i.e. IAT hooking (by providing custom IAT resolvers), and functions redirection. Yet, it is NOT focused on inline hooking and should not be confused with libraries such as MS Detours or MinHook.

LibPeConv can be used for creating PE binders, as it allows to load a PE directly from the resource, and integrate it as if it was a local code.

As well it can help you in dumping PEs from the memory, and rebuilding their IATs.

### Basic example

*The simplest usecase*: use libPeConv to manually load and run an EXE of you choice.

```C
#include <Windows.h>
#include <iostream>

#include <peconv.h> // include libPeConv header

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Args: <path to the exe>" << std::endl;
        return 0;
    }
    LPCSTR pe_path = argv[1];

    // manually load the PE file using libPeConv:
    size_t v_size = 0;
#ifdef LOAD_FROM_PATH
    //if the PE is dropped on the disk, you can load it from the file:
    BYTE* my_pe = peconv::load_pe_executable(pe_path, v_size);
#else
    size_t bufsize = 0;
    BYTE *buffer = peconv::load_file(pe_path, bufsize);

    // if the file is NOT dropped on the disk, you can load it directly from a memory buffer:
    BYTE* my_pe = peconv::load_pe_executable(buffer, bufsize, v_size);
#endif
    if (!my_pe) {
        return -1;
    }
	
    // if the loaded PE needs to access resources, you may need to connect it to the PEB:
    peconv::set_main_module_in_peb((HMODULE)my_pe);
    
    // if needed, you can run TLS callbacks before the Entry Point:
    peconv::run_tls_callbacks(my_pe, v_size);
	
    //calculate the Entry Point of the manually loaded module
    DWORD ep_rva = peconv::get_entry_point_rva(my_pe);
    if (!ep_rva) {
        return -2;
    }
    ULONG_PTR ep_va = ep_rva + (ULONG_PTR) my_pe;
    //assuming that the payload is an EXE file (not DLL) this will be the simplest prototype of the main:
    int (*new_main)() = (int(*)())ep_va;

    //call the Entry Point of the manually loaded PE:
    return new_main();
}

```

### Read more
+   [Wiki](https://github.com/hasherezade/libpeconv/wiki)
+   [Docs](https://hasherezade.github.io/libpeconv/)
+   [Examples](https://github.com/hasherezade/libpeconv/tree/master/tests)
+   [Tutorials](https://hshrzd.wordpress.com/tag/libpeconv/)
+   [Project template](https://github.com/hasherezade/libpeconv_project_template)
