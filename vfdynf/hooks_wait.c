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
Hook_Kernel32_WaitForSingleObject(
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

    return Orig_Kernel32_WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD
NTAPI
Hook_Kernel32_WaitForSingleObjectEx(
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

    return Orig_Kernel32_WaitForSingleObjectEx(hHandle,
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
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_Kernel32_WaitForMultipleObjects(nCount,
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
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_Kernel32_WaitForMultipleObjectsEx(nCount,
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
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD
NTAPI
Hook_KernelBase_WaitForSingleObjectEx(
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

    return Orig_KernelBase_WaitForSingleObjectEx(hHandle,
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
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForMultipleObjects(nCount,
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
    if ((dwMilliseconds != 0) &&
        (dwMilliseconds != INFINITE) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForMultipleObjectsEx(nCount,
                                                    lpHandles,
                                                    bWaitAll,
                                                    dwMilliseconds,
                                                    bAlertable);
}
