/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

NTSTATUS
NTAPI
Hook_NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    if (Timeout && (Timeout->QuadPart != 0) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return STATUS_TIMEOUT;
    }

    return Orig_NtWaitForSingleObject(Handle, Alertable, Timeout);
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
    if (Timeout && (Timeout->QuadPart != 0) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return STATUS_TIMEOUT;
    }

    return Orig_NtWaitForMultipleObjects(Count,
                                         Handles,
                                         WaitType,
                                         Alertable,
                                         Timeout);
}

DWORD
NTAPI
Hook_Common_WaitForSingleObject(
    _In_ PFunc_WaitForSingleObject Orig_WaitForSingleObject,
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    )
{
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD
NTAPI
Hook_Common_WaitForSingleObjectEx(
    _In_ PFunc_WaitForSingleObjectEx Orig_WaitForSingleObjectEx,
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable);
}

DWORD
NTAPI
Hook_Common_WaitForMultipleObjects(
    _In_ PFunc_WaitForMultipleObjects Orig_WaitForMultipleObjects,
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    )
{
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_WaitForMultipleObjects(nCount,
                                       lpHandles,
                                       bWaitAll,
                                       dwMilliseconds);
}

DWORD
NTAPI
Hook_Common_WaitForMultipleObjectsEx(
    _In_ PFunc_WaitForMultipleObjectsEx Orig_WaitForMultipleObjectsEx,
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_WaitForMultipleObjectsEx(nCount,
                                         lpHandles,
                                         bWaitAll,
                                         dwMilliseconds,
                                         bAlertable);
}

DWORD
NTAPI
Hook_Kernel32_WaitForSingleObject(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   WaitForSingleObject,
                                   hHandle,
                                   dwMilliseconds);
}

DWORD
NTAPI
Hook_Kernel32_WaitForSingleObjectEx(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   WaitForSingleObjectEx,
                                   hHandle,
                                   dwMilliseconds,
                                   bAlertable);
}

DWORD
NTAPI
Hook_Kernel32_WaitForMultipleObjects(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   WaitForMultipleObjects,
                                   nCount,
                                   lpHandles,
                                   bWaitAll,
                                   dwMilliseconds);
}

DWORD
NTAPI
Hook_Kernel32_WaitForMultipleObjectsEx(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   WaitForMultipleObjectsEx,
                                   nCount,
                                   lpHandles,
                                   bWaitAll,
                                   dwMilliseconds,
                                   bAlertable);
}

DWORD
NTAPI
Hook_KernelBase_WaitForSingleObject(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   WaitForSingleObject,
                                   hHandle,
                                   dwMilliseconds);
}

DWORD
NTAPI
Hook_KernelBase_WaitForSingleObjectEx(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   WaitForSingleObjectEx,
                                   hHandle,
                                   dwMilliseconds,
                                   bAlertable);
}

DWORD
NTAPI
Hook_KernelBase_WaitForMultipleObjects(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   WaitForMultipleObjects,
                                   nCount,
                                   lpHandles,
                                   bWaitAll,
                                   dwMilliseconds);
}

DWORD
NTAPI
Hook_KernelBase_WaitForMultipleObjectsEx(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   WaitForMultipleObjectsEx,
                                   nCount,
                                   lpHandles,
                                   bWaitAll,
                                   dwMilliseconds,
                                   bAlertable);
}
