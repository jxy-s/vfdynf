/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

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
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::VMem))
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return thunks::CallOriginal(&Hook_NtAllocateVirtualMemory,
                                thunks::g_Ntdll,
                                ProcessHandle,
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
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::VMem))
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return thunks::CallOriginal(&Hook_NtAllocateVirtualMemoryEx,
                                thunks::g_Ntdll,
                                ProcessHandle,
                                BaseAddress,
                                RegionSize,
                                AllocationType,
                                PageProtection,
                                ExtendedParameters,
                                ExtendedParameterCount);
}