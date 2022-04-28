/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

NTSTATUS
NTAPI
Hook_NtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::File))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtCreateFile,
                                thunks::g_Ntdll,
                                FileHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                IoStatusBlock,
                                AllocationSize,
                                FileAttributes,
                                ShareAccess,
                                CreateDisposition,
                                CreateOptions,
                                EaBuffer,
                                EaLength);
}

NTSTATUS
NTAPI
Hook_NtOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::File))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtOpenFile,
                                thunks::g_Ntdll,
                                FileHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                IoStatusBlock,
                                ShareAccess,
                                OpenOptions);
}