/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

VOID AVrfpCheckHeapAllocLimit(
    _In_ SIZE_T Size,
    _In_ PVOID Context
    )
{
    AVRF_HOOK_WITH_CONTEXT(Context);

    if (Size > AVrfProperties.HeapReasonableAllocLimit)
    {
        if (AVrfHookShouldVerifierStop())
        {
            VerifierStopMessageEx(&AVrfLayerDescriptor,
                                  VFDYNF_CODE_HEAP_ALLOC_LIMIT,
                                  Size,
                                  0,
                                  0,
                                  0,
                                  0);
        }
    }
}

PVOID
NTAPI
Hook_RtlAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    )
{
    AVRF_HOOK_CONTEXT();

    AVrfpCheckHeapAllocLimit(Size, AVrfHookGetContext());

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        if (FlagOn(Flags, HEAP_GENERATE_EXCEPTIONS))
        {
            EXCEPTION_RECORD exceptionRecord;

            exceptionRecord.ExceptionCode = (DWORD)STATUS_NO_MEMORY;
            exceptionRecord.ExceptionFlags = 0;
            exceptionRecord.ExceptionRecord = NULL;
            exceptionRecord.ExceptionAddress = AVrfHookCallerAddress();
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
    AVRF_HOOK_CONTEXT();

    AVrfpCheckHeapAllocLimit(Size, AVrfHookGetContext());

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        if (FlagOn(Flags, HEAP_GENERATE_EXCEPTIONS))
        {
            EXCEPTION_RECORD exceptionRecord;

            exceptionRecord.ExceptionCode = (DWORD)STATUS_NO_MEMORY;
            exceptionRecord.ExceptionFlags = 0;
            exceptionRecord.ExceptionRecord = NULL;
            exceptionRecord.ExceptionAddress = AVrfHookCallerAddress();
            exceptionRecord.NumberParameters = 0;

            RtlRaiseException(&exceptionRecord);
        }

        return NULL;
    }

    return Orig_RtlReAllocateHeap(HeapHandle, Flags, BaseAddress, Size);
}

HGLOBAL
WINAPI
Hook_Common_GlobalAlloc(
    _In_ PFunc_GlobalAlloc Orig_GlobalAlloc,
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    AVRF_HOOK_CONTEXT();

    AVrfpCheckHeapAllocLimit(dwBytes, AVrfHookGetContext());

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_GlobalAlloc(uFlags, dwBytes);
}

HGLOBAL
WINAPI
Hook_Common_GlobalReAlloc(
    _In_ PFunc_GlobalReAlloc Orig_GlobalReAlloc,
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    AVRF_HOOK_CONTEXT();

    AVrfpCheckHeapAllocLimit(dwBytes, AVrfHookGetContext());

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_GlobalReAlloc(hMem, dwBytes, uFlags);
}

HLOCAL
WINAPI
Hook_Common_LocalAlloc(
    _In_ PFunc_LocalAlloc Orig_LocalAlloc,
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    AVRF_HOOK_CONTEXT();

    AVrfpCheckHeapAllocLimit(uFlags, AVrfHookGetContext());

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_LocalAlloc(uFlags, uBytes);
}

HLOCAL
WINAPI
Hook_Common_LocalReAlloc(
    _In_ PFunc_LocalReAlloc Orig_LocalReAlloc,
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    AVRF_HOOK_CONTEXT();

    AVrfpCheckHeapAllocLimit(uBytes, AVrfHookGetContext());

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_LocalReAlloc(hMem, uBytes, uFlags);
}

HGLOBAL
WINAPI
Hook_Kernel32_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    GlobalAlloc,
                                    uFlags,
                                    dwBytes);
}

HGLOBAL
WINAPI
Hook_Kernel32_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    GlobalReAlloc,
                                    hMem,
                                    dwBytes,
                                    uFlags);
}

HLOCAL
WINAPI
Hook_Kernel32_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    LocalAlloc,
                                    uFlags,
                                    uBytes);
}

HLOCAL
WINAPI
Hook_Kernel32_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    return VFDYNF_LINK_COMMON_HOOK2(Kernel32,
                                    KernelBase,
                                    LocalReAlloc,
                                    hMem,
                                    uBytes,
                                    uFlags);
}

HGLOBAL
WINAPI
Hook_KernelBase_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   GlobalAlloc,
                                   uFlags,
                                   dwBytes);
}

HGLOBAL
WINAPI
Hook_KernelBase_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   GlobalReAlloc,
                                   hMem,
                                   dwBytes,
                                   uFlags);
}

HLOCAL
WINAPI
Hook_KernelBase_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   LocalAlloc,
                                   uFlags,
                                   uBytes);
}

HLOCAL
WINAPI
Hook_KernelBase_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   LocalReAlloc,
                                   hMem,
                                   uBytes,
                                   uFlags);
}
