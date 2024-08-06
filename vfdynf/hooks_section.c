/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

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

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

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

    if (NT_SUCCESS(status) &&
        (ProcessHandle == NtCurrentProcess()) &&
        AVrfShouldSubjectMemoryToInPageError(*BaseAddress) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(*BaseAddress);
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

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    status = Orig_NtMapViewOfSectionEx(SectionHandle,
                                       ProcessHandle,
                                       BaseAddress,
                                       SectionOffset,
                                       ViewSize,
                                       AllocationType,
                                       Win32Protect,
                                       ExtendedParameters,
                                       ExtendedParameterCount);

    if (NT_SUCCESS(status) &&
        (ProcessHandle == NtCurrentProcess()) &&
        AVrfShouldSubjectMemoryToInPageError(BaseAddress) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(*BaseAddress);
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
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags);
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_CreateFileMappingW(hFile,
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_CreateFileMappingA(hFile,
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_OpenFileMappingW(dwDesiredAccess,
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_OpenFileMappingA(dwDesiredAccess,
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
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_Kernel32_MapViewOfFile(hFileMappingObject,
                                         dwDesiredAccess,
                                         dwFileOffsetHigh,
                                         dwFileOffsetLow,
                                         dwNumberOfBytesToMap);

    if (result &&
        AVrfShouldSubjectMemoryToInPageError(result) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
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
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_Kernel32_MapViewOfFileEx(hFileMappingObject,
                                           dwDesiredAccess,
                                           dwFileOffsetHigh,
                                           dwFileOffsetLow,
                                           dwNumberOfBytesToMap,
                                           lpBaseAddress);

    if (result &&
        AVrfShouldSubjectMemoryToInPageError(result) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
}

BOOL
WINAPI
Hook_Kernel32_UnmapViewOfFile(
    _In_ PVOID BaseAddress
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_Kernel32_UnmapViewOfFile(BaseAddress);
}

BOOL
WINAPI
Hook_Kernel32_UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_Kernel32_UnmapViewOfFileEx(BaseAddress, UnmapFlags);
}

LPVOID
WINAPI
Hook_Kernel32_VirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_VirtualAlloc(lpAddress,
                                      dwSize,
                                      flAllocationType,
                                      flProtect);
}

LPVOID
WINAPI
Hook_Kernel32_VirtualAllocEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_VirtualAllocEx(hProcess,
                                        lpAddress,
                                        dwSize,
                                        flAllocationType,
                                        flProtect);
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_CreateFileMappingW(hFile,
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_CreateFileMappingA(hFile,
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_OpenFileMappingW(dwDesiredAccess,
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
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_OpenFileMappingA(dwDesiredAccess,
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
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_KernelBase_MapViewOfFile(hFileMappingObject,
                                           dwDesiredAccess,
                                           dwFileOffsetHigh,
                                           dwFileOffsetLow,
                                           dwNumberOfBytesToMap);

    if (result &&
        AVrfShouldSubjectMemoryToInPageError(result) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
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
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_KernelBase_MapViewOfFileEx(hFileMappingObject,
                                             dwDesiredAccess,
                                             dwFileOffsetHigh,
                                             dwFileOffsetLow,
                                             dwNumberOfBytesToMap,
                                             lpBaseAddress);

    if (result &&
        AVrfShouldSubjectMemoryToInPageError(result) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
}

BOOL
WINAPI
Hook_KernelBase_UnmapViewOfFile(
    _In_ PVOID BaseAddress
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_KernelBase_UnmapViewOfFile(BaseAddress);
}

BOOL
WINAPI
Hook_KernelBase_UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_KernelBase_UnmapViewOfFileEx(BaseAddress, UnmapFlags);
}
