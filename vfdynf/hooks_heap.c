/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

PVOID
NTAPI
Hook_RtlAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        if (FlagOn(Flags, HEAP_GENERATE_EXCEPTIONS))
        {
            EXCEPTION_RECORD exceptionRecord;

            exceptionRecord.ExceptionCode = (DWORD)STATUS_NO_MEMORY;
            exceptionRecord.ExceptionFlags = 0;
            exceptionRecord.ExceptionRecord = NULL;
            exceptionRecord.ExceptionAddress = VerifierGetAppCallerAddress(_ReturnAddress());
            exceptionRecord.NumberParameters = 0;

            RtlRaiseException(&exceptionRecord);
        }

        return NULL;
    }

    return Orig_RtlAllocateHeap(HeapHandle, Flags, Size);
}

PVOID
NTAPI
Hook_RtlReAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        if (FlagOn(Flags, HEAP_GENERATE_EXCEPTIONS))
        {
            EXCEPTION_RECORD exceptionRecord;

            exceptionRecord.ExceptionCode = (DWORD)STATUS_NO_MEMORY;
            exceptionRecord.ExceptionFlags = 0;
            exceptionRecord.ExceptionRecord = NULL;
            exceptionRecord.ExceptionAddress = VerifierGetAppCallerAddress(_ReturnAddress());
            exceptionRecord.NumberParameters = 0;

            RtlRaiseException(&exceptionRecord);
        }

        return NULL;
    }

    return Orig_RtlReAllocateHeap(HeapHandle, Flags, BaseAddress, Size);
}

HGLOBAL
WINAPI
Hook_Kernel32_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_GlobalAlloc(uFlags, dwBytes);
}

HGLOBAL
WINAPI
Hook_Kernel32_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_GlobalReAlloc(hMem, dwBytes, uFlags);
}

HLOCAL
WINAPI
Hook_Kernel32_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_LocalAlloc(uFlags, uBytes);
}

HLOCAL
WINAPI
Hook_Kernel32_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_LocalReAlloc(hMem, uBytes, uFlags);
}

HGLOBAL
WINAPI
Hook_KernelBase_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_GlobalAlloc(uFlags, dwBytes);
}

HGLOBAL
WINAPI
Hook_KernelBase_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_GlobalReAlloc(hMem, dwBytes, uFlags);
}

HLOCAL
WINAPI
Hook_KernelBase_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_LocalAlloc(uFlags, uBytes);
}

HLOCAL
WINAPI
Hook_KernelBase_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_LocalReAlloc(hMem, uBytes, uFlags);
}
