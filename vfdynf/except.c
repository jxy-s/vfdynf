/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

typedef struct _VFDYNF_GUARD_PAGE_ENTRY
{
    PVOID BaseAddress;
    SIZE_T RegionSize;
} VFDYNF_GUARD_PAGE_ENTRY, * PVFDYNF_GUARD_PAGE_ENTRY;

#define VFDYNF_GUARD_PAGE_COUNT 1024

typedef struct _VFDYNF_EXCEPT_CONTEXT
{
    PVOID Handle;
    RTL_CRITICAL_SECTION CriticalSection;
    ULONG GuardEntryCount;
    VFDYNF_GUARD_PAGE_ENTRY GuardEntries[VFDYNF_GUARD_PAGE_COUNT];
} VFDYNF_EXCEPT_CONTEXT, * PVFDYNF_EXCEPT_CONTEXT;

static VFDYNF_EXCEPT_CONTEXT AVrfpExceptContext =
{
    .Handle = NULL,
    .CriticalSection = { 0 },
    .GuardEntryCount = 0,
    .GuardEntries = { 0 },
};

VOID AVrfGuardToConvertToInPageError(
    _In_ PVOID Address
    )
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG oldProtect;

    status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  Address,
                                  MemoryBasicInformation,
                                  &mbi,
                                  sizeof(mbi),
                                  NULL);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    mbi.Protect |= PAGE_GUARD;

    status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &mbi.BaseAddress,
                                    &mbi.RegionSize,
                                    mbi.Protect,
                                    &oldProtect);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    status = RtlEnterCriticalSection(&AVrfpExceptContext.CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));

    if (AVrfpExceptContext.GuardEntryCount < VFDYNF_GUARD_PAGE_COUNT)
    {
        PVFDYNF_GUARD_PAGE_ENTRY entry;

        entry = &AVrfpExceptContext.GuardEntries[AVrfpExceptContext.GuardEntryCount++];

        entry->BaseAddress = mbi.BaseAddress;
        entry->RegionSize = mbi.RegionSize;
    }
    else
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: out of guard page slots!");
        __debugbreak();
    }

    RtlLeaveCriticalSection(&AVrfpExceptContext.CriticalSection);
}

BOOLEAN AVrfpIsGuardedAddress(
    _In_ PVOID Address
    )
{
    NTSTATUS status;
    BOOLEAN result;

    result = FALSE;

    status = RtlEnterCriticalSection(&AVrfpExceptContext.CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));

    for (ULONG i = 0; i < AVrfpExceptContext.GuardEntryCount; i++)
    {
        PVFDYNF_GUARD_PAGE_ENTRY entry;
        ULONG length;

        entry = &AVrfpExceptContext.GuardEntries[i];

        if ((Address < entry->BaseAddress) ||
            (Address >= Add2Ptr(entry->BaseAddress, entry->RegionSize)))
        {
            continue;
        }

        result = TRUE;

        AVrfpExceptContext.GuardEntryCount--;

        length = ((AVrfpExceptContext.GuardEntryCount - i) * sizeof(*entry));

        RtlMoveMemory(entry, entry + 1, length);

        //
        // Continue to ensure we clean up any other guard page entries for
        // the given address. The pages for the region are no longer guarded.
        // So make sure we clean up any other stale entires.
        //
    }

    RtlLeaveCriticalSection(&AVrfpExceptContext.CriticalSection);

    return result;
}

VOID AVrfForgetGuardForInPageError(
    _In_ PVOID Address
    )
{
    AVrfpIsGuardedAddress(Address);
}

LONG NTAPI AVrfpVectoredExceptionHandler(
    PEXCEPTION_POINTERS ExceptionInfo
    )
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
    {
        PVOID address;

        address = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

        if (AVrfpIsGuardedAddress(address))
        {
            ExceptionInfo->ExceptionRecord->ExceptionCode = (DWORD)EXCEPTION_IN_PAGE_ERROR;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOLEAN AVrfExceptProcessAttach(
    VOID
    )
{
    NTSTATUS status;

    if (AVrfpExceptContext.Handle)
    {
        return TRUE;
    }

    status = RtlInitializeCriticalSection(&AVrfpExceptContext.CriticalSection);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    AVrfpExceptContext.Handle =
        RtlAddVectoredExceptionHandler(ULONG_MAX, AVrfpVectoredExceptionHandler);

    if (!AVrfpExceptContext.Handle)
    {
        RtlDeleteCriticalSection(&AVrfpExceptContext.CriticalSection);

        return FALSE;
    }

    return TRUE;
}

VOID AVrfExceptProcessDetach(
    VOID
    )
{
    if (!AVrfpExceptContext.Handle)
    {
        return;
    }

    RtlRemoveVectoredExceptionHandler(AVrfpExceptContext.Handle);

    RtlDeleteCriticalSection(&AVrfpExceptContext.CriticalSection);

    AVrfpExceptContext.Handle = NULL;
}
