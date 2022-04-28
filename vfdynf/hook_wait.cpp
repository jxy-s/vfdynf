/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

NTSTATUS
NTAPI
Hook_NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Wait))
        {
            return STATUS_TIMEOUT;
        }
    }

    return thunks::CallOriginal(&Hook_NtWaitForSingleObject,
                                thunks::g_Ntdll,
                                Handle,
                                Alertable,
                                Timeout);
}

NTSTATUS
NTAPI
Hook_NtWaitForMultipleObjects(
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Wait))
        {
            return STATUS_TIMEOUT;
        }
    }

    return thunks::CallOriginal(&Hook_NtWaitForMultipleObjects,
                                thunks::g_Ntdll,
                                Count,
                                Handles,
                                WaitType,
                                Alertable,
                                Timeout);
}