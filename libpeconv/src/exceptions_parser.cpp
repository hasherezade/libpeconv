// Original RtlInsertInvertedFunctionTable implementation: https://github.com/bb107/MemoryModulePP

#include "peconv/exceptions_parser.h"

#include "peconv/pe_hdrs_helper.h"
#include "peconv/util.h"
#include "ntddk.h"

#ifdef _DEBUG
#include <iostream>
#endif

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

namespace details {
#define RTL_VERIFY_FLAGS_MAJOR_VERSION	0
#define RTL_VERIFY_FLAGS_MINOR_VERSION	1
#define RTL_VERIFY_FLAGS_BUILD_NUMBERS	2
#define RTL_VERIFY_FLAGS_DEFAULT		RTL_VERIFY_FLAGS_MAJOR_VERSION|RTL_VERIFY_FLAGS_MINOR_VERSION|RTL_VERIFY_FLAGS_BUILD_NUMBERS
    typedef struct _SEARCH_CONTEXT {

        IN LPBYTE SearchPattern;
        IN SIZE_T PatternSize;

        OUT LPBYTE Result;
        SIZE_T MemoryBlockSize;

    } SEARCH_CONTEXT, * PSEARCH_CONTEXT;

    typedef struct _NtVersion {
        ULONG MajorVersion;
        ULONG MinorVersion;
        ULONG BuildNumber;
    } NtVersion, * PNtVersion;

    typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 {
        PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG ExceptionDirectorySize;
    } RTL_INVERTED_FUNCTION_TABLE_ENTRY_64, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64;
    typedef struct _RTL_INVERTED_FUNCTION_TABLE_64 {
        ULONG Count;
        ULONG MaxCount;
        ULONG Epoch;
        ULONG Overflow;
        RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 Entries[0x200];
    } RTL_INVERTED_FUNCTION_TABLE_64, * PRTL_INVERTED_FUNCTION_TABLE_64;

    /*	The correct data structure for Win8+ 32 should be this.*/
     typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN8_PLUS_32 {
        PVOID EntrySEHandlerTableEncoded;
	    PVOID ImageBase;
	    ULONG ImageSize;
	    ULONG SEHandlerCount;
    } RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN8_PLUS_32, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN8_PLUS_32;
   
    typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 {
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG SEHandlerCount;
        PVOID EntrySEHandlerTableEncoded;
    } RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32;
    
    typedef struct _RTL_INVERTED_FUNCTION_TABLE_WIN7_32 {
        ULONG Count;
        ULONG MaxCount;
        ULONG Overflow;
        ULONG NextEntrySEHandlerTableEncoded;
        RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 Entries[0x200];
    } RTL_INVERTED_FUNCTION_TABLE_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_WIN7_32;

#ifdef _WIN64
    typedef _RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 _RTL_INVERTED_FUNCTION_TABLE_ENTRY, RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;
    typedef RTL_INVERTED_FUNCTION_TABLE_64 _RTL_INVERTED_FUNCTION_TABLE, RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;
#else
    typedef RTL_INVERTED_FUNCTION_TABLE_WIN7_32 _RTL_INVERTED_FUNCTION_TABLE, RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;
    typedef _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 _RTL_INVERTED_FUNCTION_TABLE_ENTRY, RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;
#endif

    typedef struct _LDR_DDAG_NODE_WIN8 {
        LIST_ENTRY Modules;							                        //0x0
        PLDR_SERVICE_TAG_RECORD ServiceTagList;				                //0x10
        ULONG LoadCount;                                                        //0x18
        ULONG ReferenceCount;                                                   //0x1c
        ULONG DependencyCount;                                                  //0x20
        PLDRP_CSLIST_DEPENDENT Dependencies;						//0x28
        PLDRP_CSLIST_INCOMMING IncomingDependencies;				//0x30
        LDR_DDAG_STATE State;                                                  //0x38
        SINGLE_LIST_ENTRY CondenseLink;									    //0x40
        ULONG PreorderNumber;                                                   //0x48
        ULONG LowestLink;                                                       //0x4c
    } LDR_DDAG_NODE_WIN8, * PLDR_DDAG_NODE_WIN8;

    //6.2.9200	Windows 8 | 2012 RTM
    typedef struct _LDR_DATA_TABLE_ENTRY_WIN8 {
        LIST_ENTRY InLoadOrderLinks;											  //0x0
        LIST_ENTRY InMemoryOrderLinks;											  //0x10
        union {
            LIST_ENTRY InInitializationOrderLinks;								  //0x20
            LIST_ENTRY InProgressLinks;										  //0x20
        };
        PVOID DllBase;                                                            //0x30
        PVOID EntryPoint;                                                         //0x38
        ULONG SizeOfImage;                                                        //0x40
        UNICODE_STRING FullDllName;											  //0x48
        UNICODE_STRING BaseDllName;											  //0x58
        union {
            UCHAR FlagGroup[4];                                                   //0x68
            ULONG Flags;                                                          //0x68
            struct {
                ULONG PackagedBinary : 1;                                         //0x68
                ULONG MarkedForRemoval : 1;                                       //0x68
                ULONG ImageDll : 1;                                               //0x68
                ULONG LoadNotificationsSent : 1;                                  //0x68
                ULONG TelemetryEntryProcessed : 1;                                //0x68
                ULONG ProcessStaticImport : 1;                                    //0x68
                ULONG InLegacyLists : 1;                                          //0x68
                ULONG InIndexes : 1;                                              //0x68
                ULONG ShimDll : 1;                                                //0x68
                ULONG InExceptionTable : 1;                                       //0x68
                ULONG ReservedFlags1 : 2;                                         //0x68
                ULONG LoadInProgress : 1;                                         //0x68
                ULONG ReservedFlags2 : 1;                                         //0x68
                ULONG EntryProcessed : 1;                                         //0x68
                ULONG ReservedFlags3 : 3;                                         //0x68
                ULONG DontCallForThreads : 1;                                     //0x68
                ULONG ProcessAttachCalled : 1;                                    //0x68
                ULONG ProcessAttachFailed : 1;                                    //0x68
                ULONG CorDeferredValidate : 1;                                    //0x68
                ULONG CorImage : 1;                                               //0x68
                ULONG DontRelocate : 1;                                           //0x68
                ULONG CorILOnly : 1;                                              //0x68
                ULONG ReservedFlags5 : 3;                                         //0x68
                ULONG Redirected : 1;                                             //0x68
                ULONG ReservedFlags6 : 2;                                         //0x68
                ULONG CompatDatabaseProcessed : 1;                                //0x68
            };
        };
        USHORT ObsoleteLoadCount;                                                 //0x6c
        USHORT TlsIndex;                                                          //0x6e
        LIST_ENTRY HashLinks;                                                    //0x70
        ULONG TimeDateStamp;                                                      //0x80
        PACTIVATION_CONTEXT EntryPointActivationContext;                         //0x88
        PVOID PatchInformation;                                                   //0x90
        PLDR_DDAG_NODE_WIN8 DdagNode;                                            //0x98
        LIST_ENTRY NodeModuleLink;                                               //0xa0
        PVOID SnapContext;						                                  //0xb0
        PVOID ParentDllBase;                                                      //0xb8
        PVOID SwitchBackContext;                                                  //0xc0
        RTL_BALANCED_NODE BaseAddressIndexNode;                                  //0xc8
        RTL_BALANCED_NODE MappingInfoIndexNode;                                  //0xe0
        ULONGLONG OriginalBase;                                                   //0xf8
        LARGE_INTEGER LoadTime;                                                  //0x100
        ULONG BaseNameHashValue;                                                  //0x108
        LDR_DLL_LOAD_REASON LoadReason;                                          //0x10c
    } LDR_DATA_TABLE_ENTRY_WIN8, * PLDR_DATA_TABLE_ENTRY_WIN8;

    static void NTAPI RtlCurrentVersion(_Out_ PNtVersion pVersion) {
        RtlGetNtVersionNumbers(
            &pVersion->MajorVersion,
            &pVersion->MinorVersion,
            &pVersion->BuildNumber
        );
    }

    static BOOL NTAPI RtlIsWindowsVersionOrGreater(
        _In_ ULONG MajorVersion,
        _In_ ULONG MinorVersion,
        _In_ ULONG BuildNumber
    ) {
        NtVersion version = { 0 };
        RtlCurrentVersion(&version);
        if (version.MajorVersion == MajorVersion) {
            if (version.MinorVersion == MinorVersion) return version.BuildNumber >= BuildNumber;
            else return (version.MinorVersion > MinorVersion);
        }
        else return version.MajorVersion > MajorVersion;
    }

    static BOOL NTAPI RtlVerifyVersion(
        _In_ ULONG MajorVersion,
        _In_ ULONG MinorVersion,
        _In_ ULONG BuildNumber,
        _In_ BYTE Flags
    ) {
        NtVersion version = { 0 };
        RtlCurrentVersion(&version);
        if (version.MajorVersion == MajorVersion &&
            ((Flags & RTL_VERIFY_FLAGS_MINOR_VERSION) ? version.MinorVersion == MinorVersion : true) &&
            ((Flags & RTL_VERIFY_FLAGS_BUILD_NUMBERS) ? version.BuildNumber == BuildNumber : true))return TRUE;
        return FALSE;
    }
#ifndef _WIN64
    static int NTAPI RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount) {
        PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfigDirectory = nullptr;
        PIMAGE_COR20_HEADER pCor20 = nullptr;
        ULONG Size = 0;

        auto hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlImageNtHeader(BaseAddress));
        //check if no seh
        if (hdrs->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
            *SEHandlerTable = *SEHandlerCount = -1;
            return 0;
        }

        //get seh table and count
        pLoadConfigDirectory = (decltype(pLoadConfigDirectory))RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size);
        if (pLoadConfigDirectory) {
            if (Size == 0x40 && pLoadConfigDirectory->Size >= 0x48u) {
                if (pLoadConfigDirectory->SEHandlerTable && pLoadConfigDirectory->SEHandlerCount) {
                    *SEHandlerTable = pLoadConfigDirectory->SEHandlerTable;
                    return *SEHandlerCount = pLoadConfigDirectory->SEHandlerCount;
                }
            }
        }

        //is .net core ?
        pCor20 = (decltype(pCor20))RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &Size);
        *SEHandlerTable = *SEHandlerCount = ((pCor20 && pCor20->Flags & 1) ? -1 : 0);
        return 0;
    }
#endif

    static PECONV_FORCEINLINE bool IsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry) {
        if (RtlIsWindowsVersionOrGreater(6, 2, 0)) { // Windows 8+
            return PLDR_DATA_TABLE_ENTRY_WIN8(entry)->DdagNode->State == LdrModulesUnloaded;
        }
        else {
            return entry->DllBase == nullptr;
        }
    }

    static NTSTATUS NTAPI RtlFindMemoryBlockFromModuleSection(
        _In_ HMODULE ModuleHandle,
        _In_ LPCSTR SectionName,
        _Inout_ PSEARCH_CONTEXT SearchContext) {

        NTSTATUS status = STATUS_SUCCESS;

#ifdef _MSC_VER
#define RtlFindMemoryBlockFromModuleSection__leave __leave
#else
#define RtlFindMemoryBlockFromModuleSection__leave return status
#endif

#ifdef _DEBUG
        std::cout << "Searching in section " << SectionName << " in module " << ModuleHandle << std::endl;
#endif

        PECONV_TRY_EXCEPT_BLOCK_START

            //
            // checks if no search pattern and length are provided
            //

            if (!SearchContext->SearchPattern || !SearchContext->PatternSize) {
                SearchContext->Result = nullptr;
                SearchContext->MemoryBlockSize = 0;
                status = STATUS_INVALID_PARAMETER;
                RtlFindMemoryBlockFromModuleSection__leave;
            }

            if (SearchContext->Result) {
                ++SearchContext->Result;
                --SearchContext->MemoryBlockSize;
            }
            else {

                //
                // if it is the first search, find the length and start address of the specified section
                //

                auto headers = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlImageNtHeader(ModuleHandle));
                PIMAGE_SECTION_HEADER section = nullptr;

                if (headers) {
                    section = IMAGE_FIRST_SECTION(headers);
                    for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
                        if (!_strnicmp(SectionName, reinterpret_cast<LPCSTR>(section->Name), 8)) {
                            SearchContext->Result = reinterpret_cast<LPBYTE>(ModuleHandle) + section->VirtualAddress;
                            SearchContext->MemoryBlockSize = section->Misc.VirtualSize;
                            break;
                        }

                        ++section;
                    }

                    if (!SearchContext->Result || !SearchContext->MemoryBlockSize || SearchContext->MemoryBlockSize < SearchContext->PatternSize) {
                        SearchContext->Result = nullptr;
                        SearchContext->MemoryBlockSize = 0;
                        status = STATUS_NOT_FOUND;
                        RtlFindMemoryBlockFromModuleSection__leave;
                    }
                }
                else {
                    status = STATUS_INVALID_PARAMETER_1;
                    RtlFindMemoryBlockFromModuleSection__leave;
                }
            }

            //
            // perform a linear search on the pattern
            //

            LPBYTE end = SearchContext->Result + SearchContext->MemoryBlockSize - SearchContext->PatternSize;
            while (SearchContext->Result <= end) {
                if (RtlCompareMemory(SearchContext->SearchPattern, SearchContext->Result, SearchContext->PatternSize) == SearchContext->PatternSize) {
                    RtlFindMemoryBlockFromModuleSection__leave;
                }

                ++SearchContext->Result;
                --SearchContext->MemoryBlockSize;
            }

            //
            // if the search fails, clear the output parameters
            //

            SearchContext->Result = nullptr;
            SearchContext->MemoryBlockSize = 0;
            status = STATUS_NOT_FOUND;
        }
        PECONV_TRY_EXCEPT_BLOCK_END
            status = GetExceptionCode();
        }

        return status;
    }

    static NTSTATUS RtlProtectMrdata(_In_ ULONG Protect, PRTL_INVERTED_FUNCTION_TABLE mrdata) {
        static PVOID MrdataBase = nullptr;
        static SIZE_T size = 0;
        NTSTATUS status;
        PVOID tmp;
        SIZE_T tmp_len;
        ULONG old;

        if (!MrdataBase) {
            MEMORY_BASIC_INFORMATION mbi= { 0 };
            status = NtQueryVirtualMemory(NtCurrentProcess(), mrdata, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
            if (!NT_SUCCESS(status))return status;
            MrdataBase = mbi.BaseAddress;
            size = mbi.RegionSize;
        }

        tmp = MrdataBase;
        tmp_len = size;
        return NtProtectVirtualMemory(NtCurrentProcess(), &tmp, &tmp_len, Protect, &old);
    }

    static PVOID RtlFindInvertedFunctionTable() {
#ifdef _WIN64
        // _RTL_INVERTED_FUNCTION_TABLE						x64
//		Count										+0x0	????????
//		MaxCount									+0x4	0x00000200
//		Epoch										+0x8	????????
//		OverFlow									+0xc	0x00000000
// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	ntdll.dll(win10) or The smallest base module
//		ExceptionDirectory							+0x10	++++++++
//		ImageBase									+0x18	++++++++
//		ImageSize									+0x20	++++++++
//		ExceptionDirectorySize						+0x24	++++++++
//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...
// ......
        HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
        LPCSTR lpSectionName = ".data";
        if (!hNtdll) return nullptr;
        auto NtdllHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlImageNtHeader(hNtdll));
        PIMAGE_NT_HEADERS ModuleHeaders = nullptr;
        _RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 entry = { 0 };
        PIMAGE_DATA_DIRECTORY dir = nullptr;
        SEARCH_CONTEXT SearchContext= { 0 };
        SearchContext.SearchPattern = reinterpret_cast<LPBYTE>(&entry);
        SearchContext.PatternSize = sizeof(entry);
        RtlSecureZeroMemory(&entry, sizeof(entry));

        // Windows 8
        if (RtlVerifyVersion(6, 2, 0, RTL_VERIFY_FLAGS_MAJOR_VERSION | RTL_VERIFY_FLAGS_MINOR_VERSION)) {
            hModule = hNtdll;
            ModuleHeaders = NtdllHeaders;
            //lpSectionName = ".data";
        }
        //Windows 8.1 ~ Windows 10 (11)
        else if (RtlIsWindowsVersionOrGreater(6, 3, 0)) {
            hModule = hNtdll;
            ModuleHeaders = NtdllHeaders;
            lpSectionName = ".mrdata";
        }
        else { //Windows 7 and below
            PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList,
                ListEntry = ListHead->Flink;
            PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
            while (ListEntry != ListHead) {
                CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                ListEntry = ListEntry->Flink;
                hModule = reinterpret_cast<HMODULE>(
                    hModule ? reinterpret_cast<HMODULE>(min(
                        reinterpret_cast<uintptr_t>(hModule),
                        reinterpret_cast<uintptr_t>(CurEntry->DllBase)
                    )) : CurEntry->DllBase
                    );
            }
            if (hModule) ModuleHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlImageNtHeader(hModule));
        }
        if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders) return nullptr;
        dir = &ModuleHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        entry.ExceptionDirectory = dir->Size ?
            reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(
                reinterpret_cast<size_t>(hModule) + dir->VirtualAddress
                ) : nullptr;
        entry.ImageBase = reinterpret_cast<PVOID>(hModule);
        entry.ImageSize = ModuleHeaders->OptionalHeader.SizeOfImage;
        entry.ExceptionDirectorySize = dir->Size;

        while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(hNtdll, lpSectionName, &SearchContext))) {
            auto tab = reinterpret_cast<PRTL_INVERTED_FUNCTION_TABLE_64>(SearchContext.Result - 0x10);
            if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->Overflow) return tab;
            else if (tab->MaxCount == 0x200 && !tab->Epoch) return tab;
        }

        return nullptr;
#else
        // _RTL_INVERTED_FUNCTION_TABLE						x86
//		Count										+0x0	????????
//		MaxCount									+0x4	0x00000200
//		Overflow									+0x8	0x00000000(Win7) ????????(Win10)
//		NextEntrySEHandlerTableEncoded				+0xc	0x00000000(Win10) ++++++++(Win7)
// _RTL_INVERTED_FUNCTION_TABLE_ENTRY[0]			+0x10	ntdll.dll(win10) or The smallest base module
//		ImageBase									+0x10	++++++++
//		ImageSize									+0x14	++++++++
//		SEHandlerCount								+0x18	++++++++
//		NextEntrySEHandlerTableEncoded				+0x1c	++++++++(Win10) ????????(Win7)
//	_RTL_INVERTED_FUNCTION_TABLE_ENTRY[1] ...		...
// ......
        HMODULE hModule = nullptr, hNtdll = GetModuleHandleW(L"ntdll.dll");
        auto NtdllHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlImageNtHeader(hNtdll));
        PIMAGE_NT_HEADERS ModuleHeaders = nullptr;
        _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 entry = { 0 };
        RtlSecureZeroMemory(&entry, sizeof(entry));
        LPCSTR lpSectionName = ".data";
        SEARCH_CONTEXT SearchContext = { 0 };
        SearchContext.SearchPattern = reinterpret_cast<LPBYTE>(&entry);
        SearchContext.PatternSize = sizeof(entry);
        PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList,
        ListEntry = ListHead->Flink;
        PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
        DWORD SEHTable, SEHCount;
        BYTE Offset = 0x20;	//sizeof(_RTL_INVERTED_FUNCTION_TABLE_ENTRY)*2

        if (RtlIsWindowsVersionOrGreater(6, 3, 0)) lpSectionName = ".mrdata";
        else if (!RtlIsWindowsVersionOrGreater(6, 2, 0)) Offset = 0xC;

        while (ListEntry != ListHead) {
            CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            ListEntry = ListEntry->Flink;
            if (IsModuleUnloaded(CurEntry))
                continue;					//skip unloaded module
            if (CurEntry->DllBase == hNtdll && Offset == 0x20)
                continue;	//Win10 skip first entry, if the base of ntdll is smallest.

            hModule = reinterpret_cast<HMODULE>(
                hModule ? reinterpret_cast<HMODULE>(min(
                    reinterpret_cast<uintptr_t>(hModule),
                    reinterpret_cast<uintptr_t>(CurEntry->DllBase)
                )) : CurEntry->DllBase
                );
        }
        ModuleHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlImageNtHeader(hModule));
        if (!hModule || !ModuleHeaders || !hNtdll || !NtdllHeaders)return nullptr;

        RtlCaptureImageExceptionValues(hModule, &SEHTable, &SEHCount);

        if (RtlIsWindowsVersionOrGreater(6, 2, 0)) {
            //memory layout is same as x64
            auto entry2 = reinterpret_cast<PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN8_PLUS_32>(&entry);
            entry2->EntrySEHandlerTableEncoded = RtlEncodeSystemPointer(reinterpret_cast<PVOID>(SEHTable));
            entry2->ImageBase = reinterpret_cast<PVOID>(hModule);
            entry2->ImageSize = ModuleHeaders->OptionalHeader.SizeOfImage;
            entry2->SEHandlerCount = SEHCount;
        }
        else {
            entry.EntrySEHandlerTableEncoded = RtlEncodeSystemPointer(reinterpret_cast<PVOID>(SEHTable));
            entry.ImageBase = reinterpret_cast<PVOID>(hModule);
            entry.ImageSize = ModuleHeaders->OptionalHeader.SizeOfImage;
            entry.SEHandlerCount = SEHCount;
        }

        while (NT_SUCCESS(RtlFindMemoryBlockFromModuleSection(hNtdll, lpSectionName, &SearchContext))) {
            PRTL_INVERTED_FUNCTION_TABLE_WIN7_32 tab = reinterpret_cast<decltype(tab)>(SearchContext.Result - Offset);

            //Note: Same memory layout for RTL_INVERTED_FUNCTION_TABLE_ENTRY in Windows 8 x86 and x64.
            if (RtlIsWindowsVersionOrGreater(6, 2, 0) && tab->MaxCount == 0x200 && !tab->NextEntrySEHandlerTableEncoded) return tab;
            else if (tab->MaxCount == 0x200 && !tab->Overflow) return tab;
        }
        return nullptr;
#endif
    }

    static VOID RtlpInsertInvertedFunctionTable(
        _In_ PRTL_INVERTED_FUNCTION_TABLE InvertedTable,
        _In_ PVOID ImageBase,
        _In_ ULONG SizeOfImage) {
#ifdef _WIN64
        ULONG CurrentSize = InvertedTable->Count;
        PIMAGE_RUNTIME_FUNCTION_ENTRY FunctionTable = nullptr;
        ULONG SizeOfTable = 0;
        BOOL IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);
        ULONG Index = static_cast<ULONG>(IsWin8OrGreater);

        if (CurrentSize != InvertedTable->MaxCount) {
            if (CurrentSize != 0) {
                while (Index < CurrentSize) {
                    if (ImageBase < InvertedTable->Entries[Index].ImageBase) break;
                    ++Index;
                }


                if (Index != CurrentSize) {
                    RtlMoveMemory(&InvertedTable->Entries[Index + 1],
                        &InvertedTable->Entries[Index],
                        (CurrentSize - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
                }
            }

            FunctionTable = reinterpret_cast<decltype(FunctionTable)>(RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &SizeOfTable));
            InvertedTable->Entries[Index].ExceptionDirectory = FunctionTable;
            InvertedTable->Entries[Index].ImageBase = ImageBase;
            InvertedTable->Entries[Index].ImageSize = SizeOfImage;
            InvertedTable->Entries[Index].ExceptionDirectorySize = SizeOfTable;
            InvertedTable->Count++;
#ifdef _DEBUG
            std::cout << "Exception table was set! " << std::endl;
#endif
        }
        else {
            IsWin8OrGreater ? (InvertedTable->Overflow = TRUE) : (InvertedTable->Epoch = TRUE);
        }

#else
        DWORD ptr = 0, count = 0;
        BOOL IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);
        ULONG Index = IsWin8OrGreater ? 1 : 0;

        if (InvertedTable->Count == InvertedTable->MaxCount) {
            if (IsWin8OrGreater)InvertedTable->NextEntrySEHandlerTableEncoded = TRUE;
            else InvertedTable->Overflow = TRUE;
            return;
        }
        while (Index < InvertedTable->Count) {
            if (ImageBase < (IsWin8OrGreater ?
                (reinterpret_cast<PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64>(&InvertedTable->Entries[Index]))->ImageBase :
                InvertedTable->Entries[Index].ImageBase))
                break;
            Index++;
        }
        if (Index != InvertedTable->Count) {
            if (IsWin8OrGreater) {
                RtlMoveMemory(&InvertedTable->Entries[Index + 1], &InvertedTable->Entries[Index],
                    (InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
            }
            else {
                RtlMoveMemory(&InvertedTable->Entries[Index].EntrySEHandlerTableEncoded,
                    Index ? &InvertedTable->Entries[Index - 1].EntrySEHandlerTableEncoded : (PVOID)&InvertedTable->NextEntrySEHandlerTableEncoded,
                    (InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
            }
        }

        RtlCaptureImageExceptionValues(ImageBase, &ptr, &count);
        if (IsWin8OrGreater) {
            //memory layout is same as x64
            auto entry = reinterpret_cast<PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN8_PLUS_32>(&InvertedTable->Entries[Index]);
            entry->EntrySEHandlerTableEncoded = RtlEncodeSystemPointer(reinterpret_cast<PVOID>(ptr));
            entry->SEHandlerCount = count;
            entry->ImageBase = ImageBase;
            entry->ImageSize = SizeOfImage;
        }
        else {
            if (Index) InvertedTable->Entries[Index - 1].EntrySEHandlerTableEncoded = RtlEncodeSystemPointer(reinterpret_cast<PVOID>(ptr));
            else InvertedTable->NextEntrySEHandlerTableEncoded = reinterpret_cast<ULONG>(RtlEncodeSystemPointer(reinterpret_cast<PVOID>(ptr)));
            InvertedTable->Entries[Index].ImageBase = ImageBase;
            InvertedTable->Entries[Index].ImageSize = SizeOfImage;
            InvertedTable->Entries[Index].SEHandlerCount = count;
        }
#ifdef _DEBUG
        std::cout << "Exception table was set! " << std::endl;
#endif
        ++InvertedTable->Count;
#endif
        return;
    }

    static NTSTATUS NTAPI RtlInsertInvertedFunctionTable(
        _In_ PVOID BaseAddress,
        _In_ ULONG ImageSize
    ) {
        auto table = reinterpret_cast<PRTL_INVERTED_FUNCTION_TABLE>(RtlFindInvertedFunctionTable());
        if (!table) {
#ifdef _DEBUG
            std::cout << "Exception table not found! " << std::endl;
#endif
            return STATUS_NOT_SUPPORTED;
        }
#ifdef _DEBUG
        std::cout << "Found exception table: " << std::hex << table << std::endl;
#endif
        BOOL need_virtual_protect = RtlIsWindowsVersionOrGreater(6, 3, 0);
        // Windows 8.1 and above require to set PAGE_READWRITE protection
#ifdef _DEBUG
        std::cout << "Need virtual protect: " << std::boolalpha << need_virtual_protect << std::endl;
#endif
        NTSTATUS status;

        if (need_virtual_protect) {
            status = RtlProtectMrdata(PAGE_READWRITE, table);
            if (!NT_SUCCESS(status))return status;
        }
        RtlpInsertInvertedFunctionTable(table, BaseAddress, ImageSize);
        if (need_virtual_protect) {
            status = RtlProtectMrdata(PAGE_READONLY, table);
            if (!NT_SUCCESS(status))return status;
        }
        // Windows 8+ versons have different structure than Windows 7 and below
        return (RtlIsWindowsVersionOrGreater(6, 2, 0) ? PRTL_INVERTED_FUNCTION_TABLE_64(table)->Overflow : PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(table)->Overflow) ?
            STATUS_NO_MEMORY : STATUS_SUCCESS;
    }
}

bool peconv::setup_exceptions(IN BYTE* modulePtr, IN size_t moduleSize)
{
    if (moduleSize == 0) {
        const DWORD img_size = get_image_size(reinterpret_cast<BYTE*>(modulePtr));
        if (!img_size) {
            return false; // invalid image
        }
        moduleSize = img_size;
    }
    return NT_SUCCESS(details::RtlInsertInvertedFunctionTable(modulePtr, (ULONG)moduleSize)) ? true : false;
}