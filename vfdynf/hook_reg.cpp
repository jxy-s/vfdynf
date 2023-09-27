/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <pch.h>

NTSTATUS
NTAPI
Hook_NtCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Reg))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtCreateKey,
                                thunks::g_Ntdll,
                                KeyHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                TitleIndex,
                                Class,
                                CreateOptions,
                                Disposition);
}

NTSTATUS
NTAPI
Hook_NtOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Reg))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtOpenKey,
                                thunks::g_Ntdll,
                                KeyHandle,
                                DesiredAccess,
                                ObjectAttributes);
}

NTSTATUS
NTAPI
Hook_NtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Reg))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtSetValueKey,
                                thunks::g_Ntdll,
                                KeyHandle,
                                ValueName,
                                TitleIndex,
                                Type,
                                Data,
                                DataSize);
}
