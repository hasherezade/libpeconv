/**
* @file
* @brief   Definitions of various versions of Load Config Directory (new fields added with new versions for Windows).
*/

#pragma once

#include <windows.h>
#include <pshpack4.h>

namespace peconv {

    /**
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY: a structure used by IMAGE_LOAD_CONFIG_DIR - the Windows 10 version.
    */
    typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY_W10 {
        WORD    Flags;          // Flags to indicate if CI information is available, etc.
        WORD    Catalog;        // 0xFFFF means not available
        DWORD   CatalogOffset;
        DWORD   Reserved;       // Additional bitmask to be defined later
    } IMAGE_LOAD_CONFIG_CODE_INTEGRITY_W10;

    /**
    IMAGE_LOAD_CONFIG_DIR32: the Windows 10 version.
    */
    typedef struct _IMAGE_LOAD_CONFIG_DIR32_W10 {
        DWORD   Size;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   GlobalFlagsClear;
        DWORD   GlobalFlagsSet;
        DWORD   CriticalSectionDefaultTimeout;
        DWORD   DeCommitFreeBlockThreshold;
        DWORD   DeCommitTotalFreeThreshold;
        DWORD   LockPrefixTable;                // VA
        DWORD   MaximumAllocationSize;
        DWORD   VirtualMemoryThreshold;
        DWORD   ProcessHeapFlags;
        DWORD   ProcessAffinityMask;
        WORD    CSDVersion;
        WORD    DependentLoadFlags;
        DWORD   EditList;                       // VA
        DWORD   SecurityCookie;                 // VA
        DWORD   SEHandlerTable;                 // VA
        DWORD   SEHandlerCount;
        DWORD   GuardCFCheckFunctionPointer;    // VA
        DWORD   GuardCFDispatchFunctionPointer; // VA
        DWORD   GuardCFFunctionTable;           // VA
        DWORD   GuardCFFunctionCount;
        DWORD   GuardFlags;
        IMAGE_LOAD_CONFIG_CODE_INTEGRITY_W10 CodeIntegrity;
        DWORD   GuardAddressTakenIatEntryTable; // VA
        DWORD   GuardAddressTakenIatEntryCount;
        DWORD   GuardLongJumpTargetTable;       // VA
        DWORD   GuardLongJumpTargetCount;
        DWORD   DynamicValueRelocTable;         // VA
        DWORD   CHPEMetadataPointer;
        DWORD   GuardRFFailureRoutine;          // VA
        DWORD   GuardRFFailureRoutineFunctionPointer; // VA
        DWORD   DynamicValueRelocTableOffset;
        WORD    DynamicValueRelocTableSection;
        WORD    Reserved2;
        DWORD   GuardRFVerifyStackPointerFunctionPointer; // VA
        DWORD   HotPatchTableOffset;
        DWORD   Reserved3;
        DWORD   EnclaveConfigurationPointer;    // VA
    } IMAGE_LOAD_CONFIG_DIR32_W10;

    /**
    IMAGE_LOAD_CONFIG_DIR64: the Windows 10 version.
    */
    typedef struct _IMAGE_LOAD_CONFIG_DIR64_W10 {
        DWORD      Size;
        DWORD      TimeDateStamp;
        WORD       MajorVersion;
        WORD       MinorVersion;
        DWORD      GlobalFlagsClear;
        DWORD      GlobalFlagsSet;
        DWORD      CriticalSectionDefaultTimeout;
        ULONGLONG  DeCommitFreeBlockThreshold;
        ULONGLONG  DeCommitTotalFreeThreshold;
        ULONGLONG  LockPrefixTable;                // VA
        ULONGLONG  MaximumAllocationSize;
        ULONGLONG  VirtualMemoryThreshold;
        ULONGLONG  ProcessAffinityMask;
        DWORD      ProcessHeapFlags;
        WORD       CSDVersion;
        WORD       DependentLoadFlags;
        ULONGLONG  EditList;                       // VA
        ULONGLONG  SecurityCookie;                 // VA
        ULONGLONG  SEHandlerTable;                 // VA
        ULONGLONG  SEHandlerCount;
        ULONGLONG  GuardCFCheckFunctionPointer;    // VA
        ULONGLONG  GuardCFDispatchFunctionPointer; // VA
        ULONGLONG  GuardCFFunctionTable;           // VA
        ULONGLONG  GuardCFFunctionCount;
        DWORD      GuardFlags;
        IMAGE_LOAD_CONFIG_CODE_INTEGRITY_W10 CodeIntegrity;
        ULONGLONG  GuardAddressTakenIatEntryTable; // VA
        ULONGLONG  GuardAddressTakenIatEntryCount;
        ULONGLONG  GuardLongJumpTargetTable;       // VA
        ULONGLONG  GuardLongJumpTargetCount;
        ULONGLONG  DynamicValueRelocTable;         // VA
        ULONGLONG  CHPEMetadataPointer;            // VA
        ULONGLONG  GuardRFFailureRoutine;          // VA
        ULONGLONG  GuardRFFailureRoutineFunctionPointer; // VA
        DWORD      DynamicValueRelocTableOffset;
        WORD       DynamicValueRelocTableSection;
        WORD       Reserved2;
        ULONGLONG  GuardRFVerifyStackPointerFunctionPointer; // VA
        DWORD      HotPatchTableOffset;
        DWORD      Reserved3;
        ULONGLONG  EnclaveConfigurationPointer;     // VA
    } IMAGE_LOAD_CONFIG_DIR64_W10;

    /**
    IMAGE_LOAD_CONFIG_DIR32: the Windows 8 version.
    */
    typedef struct _IMAGE_LOAD_CONFIG_DIR32_W8 {
        DWORD   Size;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   GlobalFlagsClear;
        DWORD   GlobalFlagsSet;
        DWORD   CriticalSectionDefaultTimeout;
        DWORD   DeCommitFreeBlockThreshold;
        DWORD   DeCommitTotalFreeThreshold;
        DWORD   LockPrefixTable;                // VA
        DWORD   MaximumAllocationSize;
        DWORD   VirtualMemoryThreshold;
        DWORD   ProcessHeapFlags;
        DWORD   ProcessAffinityMask;
        WORD    CSDVersion;
        WORD    DependentLoadFlags;
        DWORD   EditList;                       // VA
        DWORD   SecurityCookie;                 // VA
        DWORD   SEHandlerTable;                 // VA
        DWORD   SEHandlerCount;
        DWORD   GuardCFCheckFunctionPointer;    // VA
        DWORD   GuardCFDispatchFunctionPointer; // VA
        DWORD   GuardCFFunctionTable;           // VA
        DWORD   GuardCFFunctionCount;
        DWORD   GuardFlags;
    } IMAGE_LOAD_CONFIG_DIR32_W8;

    /**
    IMAGE_LOAD_CONFIG_DIR64: the Windows 8 version.
    */
    typedef struct _IMAGE_LOAD_CONFIG_DIR64_W8 {
        DWORD      Size;
        DWORD      TimeDateStamp;
        WORD       MajorVersion;
        WORD       MinorVersion;
        DWORD      GlobalFlagsClear;
        DWORD      GlobalFlagsSet;
        DWORD      CriticalSectionDefaultTimeout;
        ULONGLONG  DeCommitFreeBlockThreshold;
        ULONGLONG  DeCommitTotalFreeThreshold;
        ULONGLONG  LockPrefixTable;                // VA
        ULONGLONG  MaximumAllocationSize;
        ULONGLONG  VirtualMemoryThreshold;
        ULONGLONG  ProcessAffinityMask;
        DWORD      ProcessHeapFlags;
        WORD       CSDVersion;
        WORD       DependentLoadFlags;
        ULONGLONG  EditList;                       // VA
        ULONGLONG  SecurityCookie;                 // VA
        ULONGLONG  SEHandlerTable;                 // VA
        ULONGLONG  SEHandlerCount;
        ULONGLONG  GuardCFCheckFunctionPointer;    // VA
        ULONGLONG  GuardCFDispatchFunctionPointer; // VA
        ULONGLONG  GuardCFFunctionTable;           // VA
        ULONGLONG  GuardCFFunctionCount;
        DWORD      GuardFlags;
    } IMAGE_LOAD_CONFIG_DIR64_W8;


    /**
    IMAGE_LOAD_CONFIG_DIR32: the Windows 7 version.
    */
    typedef struct _IMAGE_LOAD_CONFIG_DIR32_W7 {
        DWORD   Size;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   GlobalFlagsClear;
        DWORD   GlobalFlagsSet;
        DWORD   CriticalSectionDefaultTimeout;
        DWORD   DeCommitFreeBlockThreshold;
        DWORD   DeCommitTotalFreeThreshold;
        DWORD   LockPrefixTable;                // VA
        DWORD   MaximumAllocationSize;
        DWORD   VirtualMemoryThreshold;
        DWORD   ProcessHeapFlags;
        DWORD   ProcessAffinityMask;
        WORD    CSDVersion;
        WORD    DependentLoadFlags;
        DWORD   EditList;                       // VA
        DWORD   SecurityCookie;                 // VA
        DWORD   SEHandlerTable;                 // VA
        DWORD   SEHandlerCount;
    } IMAGE_LOAD_CONFIG_DIR32_W7;

    /**
    IMAGE_LOAD_CONFIG_DIR64: the Windows 7 version. 
    */
    typedef struct _IMAGE_LOAD_CONFIG_DIR64_W7 {
        DWORD      Size;
        DWORD      TimeDateStamp;
        WORD       MajorVersion;
        WORD       MinorVersion;
        DWORD      GlobalFlagsClear;
        DWORD      GlobalFlagsSet;
        DWORD      CriticalSectionDefaultTimeout;
        ULONGLONG  DeCommitFreeBlockThreshold;
        ULONGLONG  DeCommitTotalFreeThreshold;
        ULONGLONG  LockPrefixTable;                // VA
        ULONGLONG  MaximumAllocationSize;
        ULONGLONG  VirtualMemoryThreshold;
        ULONGLONG  ProcessAffinityMask;
        DWORD      ProcessHeapFlags;
        WORD       CSDVersion;
        WORD       DependentLoadFlags;
        ULONGLONG  EditList;                       // VA
        ULONGLONG  SecurityCookie;                 // VA
        ULONGLONG  SEHandlerTable;                 // VA
        ULONGLONG  SEHandlerCount;
    } IMAGE_LOAD_CONFIG_DIR64_W7;
}; //namespace peconv

#include <poppack.h>
