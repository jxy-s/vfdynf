/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

NTSTATUS
NTAPI
Hook_NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtAllocateVirtualMemory(ProcessHandle,
                                        BaseAddress,
                                        ZeroBits,
                                        RegionSize,
                                        AllocationType,
                                        Protect);
}

NTSTATUS
NTAPI
Hook_NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtAllocateVirtualMemoryEx(ProcessHandle,
                                          BaseAddress,
                                          RegionSize,
                                          AllocationType,
                                          PageProtection,
                                          ExtendedParameters,
                                          ExtendedParameterCount);
}

LPVOID
WINAPI
Hook_Common_VirtualAlloc(
    _In_ PFunc_VirtualAlloc Orig_VirtualAlloc,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID
WINAPI
Hook_Common_VirtualAllocEx(
    _In_ PFunc_VirtualAllocEx Orig_VirtualAllocEx,
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_VirtualAllocEx(hProcess,
                               lpAddress,
                               dwSize,
                               flAllocationType,
                               flProtect);
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   VirtualAlloc,
                                   lpAddress,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   VirtualAllocEx,
                                   hProcess,
                                   lpAddress,
                                   dwSize,
                                   flAllocationType,
                                   flProtect);
}


LPVOID
WINAPI
Hook_KernelBase_VirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   VirtualAlloc,
                                   lpAddress,
                                   dwSize,
                                   flAllocationType,
                                   flProtect);
}

LPVOID
WINAPI
Hook_KernelBase_VirtualAllocEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   VirtualAllocEx,
                                   hProcess,
                                   lpAddress,
                                   dwSize,
                                   flAllocationType,
                                   flProtect);
}
