/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

NTSTATUS
NTAPI
Hook_NtCreateEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Event))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtCreateEvent,
                                thunks::g_Ntdll,
                                EventHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                EventType,
                                InitialState);
}

NTSTATUS
NTAPI
Hook_NtOpenEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Event))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtOpenEvent,
                                thunks::g_Ntdll,
                                EventHandle,
                                DesiredAccess,
                                ObjectAttributes);
}
