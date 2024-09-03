/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

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
    AVRF_HOOK_CONTEXT();

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateEvent(EventHandle,
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
    AVRF_HOOK_CONTEXT();

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
}

HANDLE
WINAPI
Hook_Common_CreateEventA(
    _In_ PFunc_CreateEventA Orig_CreateEventA,
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    )
{
    AVRF_HOOK_CONTEXT();

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_CreateEventA(lpEventAttributes,
                             bManualReset,
                             bInitialState,
                             lpName);
}

HANDLE
WINAPI
Hook_Common_CreateEventW(
    _In_ PFunc_CreateEventW Orig_CreateEventW,
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    )
{
    AVRF_HOOK_CONTEXT();

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_CreateEventW(lpEventAttributes,
                             bManualReset,
                             bInitialState,
                             lpName);
}

HANDLE
WINAPI
Hook_Common_OpenEventA(
    _In_ PFunc_OpenEventA Orig_CreateEventA,
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    AVRF_HOOK_CONTEXT();

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_CreateEventA(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE
WINAPI
Hook_Common_OpenEventW(
    _In_ PFunc_OpenEventW Orig_OpenEventW,
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    AVRF_HOOK_CONTEXT();

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_OpenEventW(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE
WINAPI
Hook_Kernel32_CreateEventA(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    CreateEventA,
                                    lpEventAttributes,
                                    bManualReset,
                                    bInitialState,
                                    lpName);
}

HANDLE
WINAPI
Hook_Kernel32_CreateEventW(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    CreateEventW,
                                    lpEventAttributes,
                                    bManualReset,
                                    bInitialState,
                                    lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenEventA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    OpenEventA,
                                    dwDesiredAccess,
                                    bInheritHandle,
                                    lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenEventW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    OpenEventW,
                                    dwDesiredAccess,
                                    bInheritHandle,
                                    lpName);
}

HANDLE
WINAPI
Hook_KernelBase_CreateEventA(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   CreateEventA,
                                   lpEventAttributes,
                                   bManualReset,
                                   bInitialState,
                                   lpName);
}

HANDLE
WINAPI
Hook_KernelBase_CreateEventW(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   CreateEventW,
                                   lpEventAttributes,
                                   bManualReset,
                                   bInitialState,
                                   lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenEventA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   OpenEventA,
                                   dwDesiredAccess,
                                   bInheritHandle,
                                   lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenEventW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   OpenEventW,
                                   dwDesiredAccess,
                                   bInheritHandle,
                                   lpName);
}
