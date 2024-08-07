/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

_Must_inspect_result_
BOOLEAN AVrfpShouldSubjectMemoryToFault(
    _In_ PVOID Address,
    _Out_ PSIZE_T RegionSize
    )
{
    NTSTATUS status;
    MEMORY_REGION_INFORMATION regionInfo;

    *RegionSize = 0;

    //
    // Some of the information classes here might not be supported on older
    // OSes. That's fine, we fail safe and do not inject a fault unless we're
    // confident it's appropriate.
    //

    status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  Address,
                                  MemoryRegionInformationEx,
                                  &regionInfo,
                                  sizeof(regionInfo),
                                  NULL);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    *RegionSize = regionInfo.RegionSize;

    if (regionInfo.MappedDataFile)
    {
        //
        // Inject faults for data mappings.
        //
        return TRUE;
    }

    if (regionInfo.MappedPageFile)
    {
        //
        // Do not inject faults for page file backed sections.
        //
        // https://learn.microsoft.com/en-us/windows/win32/memory/reading-and-writing-from-a-file-view
        // Reading from or writing to a file view of a file other than the page
        // file can cause an EXCEPTION_IN_PAGE_ERROR exception.
        //
        return FALSE;
    }

    if (regionInfo.MappedImage)
    {
        MEMORY_IMAGE_INFORMATION imageInfo;

        //
        // Only inject faults for SEC_IMAGE_NO_EXECUTE.
        //

        status = NtQueryVirtualMemory(NtCurrentProcess(),
                                      Address,
                                      MemoryImageInformation,
                                      &imageInfo,
                                      sizeof(imageInfo),
                                      NULL);
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        if (imageInfo.ImageNotExecutable)
        {
            return TRUE;
        }

        return FALSE;
    }

    //
    // If we aren't sure do not inject faults.
    //

    return FALSE;
}

NTSTATUS
NTAPI
Hook_NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateSection(SectionHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                MaximumSize,
                                SectionPageProtection,
                                AllocationAttributes,
                                FileHandle);
}

NTSTATUS
NTAPI
Hook_NtCreateSectionEx(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateSectionEx(SectionHandle,
                                  DesiredAccess,
                                  ObjectAttributes,
                                  MaximumSize,
                                  SectionPageProtection,
                                  AllocationAttributes,
                                  FileHandle,
                                  ExtendedParameters,
                                  ExtendedParameterCount);
}

NTSTATUS
NTAPI
Hook_NtOpenSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS
NTAPI
Hook_NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    )
{
    NTSTATUS status;
    SIZE_T regionSize;
    BOOLEAN strict;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    strict = (*BaseAddress || ZeroBits);

    status = Orig_NtMapViewOfSection(SectionHandle,
                                     ProcessHandle,
                                     BaseAddress,
                                     ZeroBits,
                                     CommitSize,
                                     SectionOffset,
                                     ViewSize,
                                     InheritDisposition,
                                     AllocationType,
                                     Win32Protect);

    if (!NT_SUCCESS(status) || (ProcessHandle != NtCurrentProcess()))
    {
        return status;
    }

    if (!AVrfpShouldSubjectMemoryToFault(*BaseAddress, &regionSize))
    {
        return status;
    }

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(*BaseAddress);
    }
    else if (!strict && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_MMAP))
    {
        *BaseAddress = AVrfFuzzMemoryMapping(*BaseAddress, regionSize);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtMapViewOfSectionEx(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    NTSTATUS status;
    SIZE_T regionSize;
    BOOLEAN strict;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    strict = (*BaseAddress || ExtendedParameterCount);

    status = Orig_NtMapViewOfSectionEx(SectionHandle,
                                       ProcessHandle,
                                       BaseAddress,
                                       SectionOffset,
                                       ViewSize,
                                       AllocationType,
                                       Win32Protect,
                                       ExtendedParameters,
                                       ExtendedParameterCount);

    if (!NT_SUCCESS(status) || (ProcessHandle != NtCurrentProcess()))
    {
        return status;
    }

    if (!AVrfpShouldSubjectMemoryToFault(*BaseAddress, &regionSize))
    {
        return status;
    }

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(*BaseAddress);
    }
    else if (!strict && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_MMAP))
    {
        *BaseAddress = AVrfFuzzMemoryMapping(*BaseAddress, regionSize);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    )
{
    if ((ProcessHandle == NtCurrentProcess()) && BaseAddress)
    {
        BaseAddress = AVrfForgetFuzzedMemoryMapping(BaseAddress);
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS
NTAPI
Hook_NtUnmapViewOfSectionEx(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags
    )
{
    if ((ProcessHandle == NtCurrentProcess()) && BaseAddress)
    {
        BaseAddress = AVrfForgetFuzzedMemoryMapping(BaseAddress);
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags);
}

HANDLE
WINAPI
Hook_Common_CreateFileMappingW(
    _In_ PFunc_CreateFileMappingW Orig_CreateFileMappingW,
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_CreateFileMappingW(hFile,
                                   lpFileMappingAttributes,
                                   flProtect,
                                   dwMaximumSizeHigh,
                                   dwMaximumSizeLow,
                                   lpName);
}

HANDLE
WINAPI
Hook_Common_CreateFileMappingA(
    _In_ PFunc_CreateFileMappingA Orig_CreateFileMappingA,
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_CreateFileMappingA(hFile,
                                   lpFileMappingAttributes,
                                   flProtect,
                                   dwMaximumSizeHigh,
                                   dwMaximumSizeLow,
                                   lpName);
}

HANDLE
WINAPI
Hook_Common_OpenFileMappingW(
    _In_ PFunc_OpenFileMappingW Orig_OpenFileMappingW,
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_OpenFileMappingW(dwDesiredAccess,
                                 bInheritHandle,
                                 lpName);
}

HANDLE
WINAPI
Hook_Common_OpenFileMappingA(
    _In_ PFunc_OpenFileMappingA Orig_OpenFileMappingA,
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_OpenFileMappingA(dwDesiredAccess,
                                 bInheritHandle,
                                 lpName);
}

LPVOID
WINAPI
Hook_Common_MapViewOfFile(
    _In_ PFunc_MapViewOfFile Orig_MapViewOfFile,
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    )
{
    LPVOID result;
    SIZE_T regionSize;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_MapViewOfFile(hFileMappingObject,
                                dwDesiredAccess,
                                dwFileOffsetHigh,
                                dwFileOffsetLow,
                                dwNumberOfBytesToMap);

    if (!result)
    {
        return result;
    }

    if (!AVrfpShouldSubjectMemoryToFault(result, &regionSize))
    {
        return result;
    }

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }
    else if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_MMAP))
    {
        result = AVrfFuzzMemoryMapping(result, regionSize);
    }

    return result;
}

LPVOID
WINAPI
Hook_Common_MapViewOfFileEx(
    _In_ PFunc_MapViewOfFileEx Orig_MapViewOfFileEx,
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress
    )
{
    LPVOID result;
    SIZE_T regionSize;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_MapViewOfFileEx(hFileMappingObject,
                                  dwDesiredAccess,
                                  dwFileOffsetHigh,
                                  dwFileOffsetLow,
                                  dwNumberOfBytesToMap,
                                  lpBaseAddress);

    if (!result)
    {
        return result;
    }

    if (!AVrfpShouldSubjectMemoryToFault(result, &regionSize))
    {
        return result;
    }

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }
    else if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_MMAP))
    {
        result = AVrfFuzzMemoryMapping(result, regionSize);
    }

    return result;
}

BOOL
WINAPI
Hook_Common_UnmapViewOfFile(
    _In_ PFunc_UnmapViewOfFile Orig_UnmapViewOfFile,
    _In_ PVOID BaseAddress
    )
{
    if (BaseAddress)
    {
        BaseAddress = AVrfForgetFuzzedMemoryMapping(BaseAddress);
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_UnmapViewOfFile(BaseAddress);
}

BOOL
WINAPI
Hook_Common_UnmapViewOfFileEx(
    _In_ PFunc_UnmapViewOfFileEx Orig_UnmapViewOfFileEx,
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    if (BaseAddress)
    {
        BaseAddress = AVrfForgetFuzzedMemoryMapping(BaseAddress);
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_UnmapViewOfFileEx(BaseAddress, UnmapFlags);
}

HANDLE
WINAPI
Hook_Kernel32_CreateFileMappingW(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   CreateFileMappingW,
                                   hFile,
                                   lpFileMappingAttributes,
                                   flProtect,
                                   dwMaximumSizeHigh,
                                   dwMaximumSizeLow,
                                   lpName);
}

HANDLE
WINAPI
Hook_Kernel32_CreateFileMappingA(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   CreateFileMappingA,
                                   hFile,
                                   lpFileMappingAttributes,
                                   flProtect,
                                   dwMaximumSizeHigh,
                                   dwMaximumSizeLow,
                                   lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenFileMappingW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   OpenFileMappingW,
                                   dwDesiredAccess,
                                   bInheritHandle,
                                   lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenFileMappingA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   OpenFileMappingA,
                                   dwDesiredAccess,
                                   bInheritHandle,
                                   lpName);
}

LPVOID
WINAPI
Hook_Kernel32_MapViewOfFile(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   MapViewOfFile,
                                   hFileMappingObject,
                                   dwDesiredAccess,
                                   dwFileOffsetHigh,
                                   dwFileOffsetLow,
                                   dwNumberOfBytesToMap);
}

LPVOID
WINAPI
Hook_Kernel32_MapViewOfFileEx(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   MapViewOfFileEx,
                                   hFileMappingObject,
                                   dwDesiredAccess,
                                   dwFileOffsetHigh,
                                   dwFileOffsetLow,
                                   dwNumberOfBytesToMap,
                                   lpBaseAddress);
}

BOOL
WINAPI
Hook_Kernel32_UnmapViewOfFile(
    _In_ PVOID BaseAddress
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   UnmapViewOfFile,
                                   BaseAddress);
}

BOOL
WINAPI
Hook_Kernel32_UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   UnmapViewOfFileEx,
                                   BaseAddress,
                                   UnmapFlags);
}

HANDLE
WINAPI
Hook_KernelBase_CreateFileMappingW(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   CreateFileMappingW,
                                   hFile,
                                   lpFileMappingAttributes,
                                   flProtect,
                                   dwMaximumSizeHigh,
                                   dwMaximumSizeLow,
                                   lpName);
}

HANDLE
WINAPI
Hook_KernelBase_CreateFileMappingA(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   CreateFileMappingA,
                                   hFile,
                                   lpFileMappingAttributes,
                                   flProtect,
                                   dwMaximumSizeHigh,
                                   dwMaximumSizeLow,
                                   lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenFileMappingW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   OpenFileMappingW,
                                   dwDesiredAccess,
                                   bInheritHandle,
                                   lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenFileMappingA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   OpenFileMappingA,
                                   dwDesiredAccess,
                                   bInheritHandle,
                                   lpName);
}

LPVOID
WINAPI
Hook_KernelBase_MapViewOfFile(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   MapViewOfFile,
                                   hFileMappingObject,
                                   dwDesiredAccess,
                                   dwFileOffsetHigh,
                                   dwFileOffsetLow,
                                   dwNumberOfBytesToMap);
}

LPVOID
WINAPI
Hook_KernelBase_MapViewOfFileEx(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   MapViewOfFileEx,
                                   hFileMappingObject,
                                   dwDesiredAccess,
                                   dwFileOffsetHigh,
                                   dwFileOffsetLow,
                                   dwNumberOfBytesToMap,
                                   lpBaseAddress);
}

BOOL
WINAPI
Hook_KernelBase_UnmapViewOfFile(
    _In_ PVOID BaseAddress
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   UnmapViewOfFile,
                                   BaseAddress);
}

BOOL
WINAPI
Hook_KernelBase_UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   UnmapViewOfFileEx,
                                   BaseAddress,
                                   UnmapFlags);
}
