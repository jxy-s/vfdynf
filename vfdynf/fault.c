/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <delayld.h>

typedef struct _VFDYNF_FAULT_ENUM_MODULES_CONTEXT
{
    PVOID CallerAddress;
    PCRE2_HANDLE Regex;
    BOOLEAN Result;
} VFDYNF_FAULT_ENUM_MODULES_CONTEXT, *PVFDYNF_FAULT_ENUM_MODULES_CONTEXT;

typedef struct _VFDYNF_EXCLUSION_REGEX
{
    ULONG Count;
    PPCRE2_HANDLE Regex;
} VFDYNF_EXCLUSION_REGEX, *PVFDYNF_EXCLUSION_REGEX;

typedef struct _VFDYNF_FAULT_COUNT
{
    volatile LONG False;
    volatile LONG True;
} VFDYNF_FAULT_COUNT, *PVFDYNF_FAULT_COUNT;

typedef struct _VFDYNF_FAULT_CONTEXT
{
    BOOLEAN Initialized;
    ULONG TypeBase;
    LARGE_INTEGER SymTimeout;
    RTL_CRITICAL_SECTION CriticalSection;
    ULONG64 LastClear;
    AVRF_STACK_TABLE StackTable;
    BOOLEAN RegexInitialized;
    PCRE2_HANDLE IncludeRegex;
    VFDYNF_EXCLUSION_REGEX Exclusions;
    VFDYNF_FAULT_COUNT TypeCount[VFDYNF_FAULT_TYPE_COUNT];
    PCRE2_HANDLE TypeIncludeRegex[VFDYNF_FAULT_TYPE_COUNT];
    VFDYNF_EXCLUSION_REGEX TypeExclusions[VFDYNF_FAULT_TYPE_COUNT];
} VFDYNF_FAULT_CONTEXT, *PVFDYNF_FAULT_CONTEXT;

static VFDYNF_FAULT_CONTEXT AVrfpFaultContext =
{
    .Initialized = FALSE,
    .TypeBase = ULONG_MAX,
    .SymTimeout = AVRF_TIMEOUT(1000),
    .CriticalSection = { 0 },
    .LastClear = 0,
    .StackTable = { 0 },
    .RegexInitialized = FALSE,
    .IncludeRegex = { 0 },
    .Exclusions = { 0 },
    .TypeCount = { 0 },
    .TypeIncludeRegex = { 0 },
    .TypeExclusions = { 0 },
};

ULONG AVrfpFaultTypeIndex(
    _In_ ULONG FaultType
    )
{
    ULONG index;

    BitScanReverse(&index, FaultType);

    return index;
}

ULONG AVrfpFaultTypeClass(
    _In_ ULONG FaultType
    )
{
    AVRF_ASSERT(AVrfpFaultContext.TypeBase != ULONG_MAX);

    return (AVrfpFaultContext.TypeBase + AVrfpFaultTypeIndex(FaultType));
}

BOOLEAN AVrfpInitExclusionsRegexInternal(
    _In_ PWCHAR Pattern,
    _Out_ PVFDYNF_EXCLUSION_REGEX Exclusion
    )
{
    ULONG offset;
    ULONG count;

    offset = 0;
    count = 0;
    for (;;)
    {
        UNICODE_STRING pattern;

        RtlInitUnicodeString(&pattern, &Pattern[offset]);
        if (!pattern.Length)
        {
            break;
        }

        count++;

        offset += ((pattern.Length / sizeof(WCHAR)) + 1);
    }

    if (!count)
    {
        Exclusion->Count = 0;
        Exclusion->Regex = NULL;
        return TRUE;
    }

    Exclusion->Count = count;
    Exclusion->Regex = RtlAllocateHeap(RtlProcessHeap(),
                                       0,
                                       count * sizeof(PCRE2_HANDLE));
    if (!Exclusion->Regex)
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to allocate exclusion regex");

        __debugbreak();
        return FALSE;
    }

    offset = 0;
    count = 0;
    for (;;)
    {
        NTSTATUS status;
        UNICODE_STRING pattern;
        PCRE2_HANDLE regex;

        RtlInitUnicodeString(&pattern, &Pattern[offset]);
        if (!pattern.Length)
        {
            break;
        }

        status = Pcre2Compile(&regex, &pattern);
        if (!NT_SUCCESS(status))
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "regex failed to compile (0x%08x)",
                         status);

            __debugbreak();
            return FALSE;
        }

        AVRF_ASSERT(count < Exclusion->Count);

        Exclusion->Regex[count++] = regex;

        offset += ((pattern.Length / sizeof(WCHAR)) + 1);
    }

    return TRUE;
}

BOOLEAN AVrfpInitExclusionsRegex(
    VOID
    )
{
    //
    // The exclusions regular expressions is a REG_MULTI_SZ from the properties
    // verifier loads on our behalf. Parse each block of the multi terminated
    // string into the regex vector. We do this so we don't have to construct
    // the regex object every time.
    //

    if (!AVrfpInitExclusionsRegexInternal(AVrfProperties.ExclusionsRegex,
                                          &AVrfpFaultContext.Exclusions))
    {
        return FALSE;
    }

    for (ULONG i = 0; i < VFDYNF_FAULT_TYPE_COUNT; i++)
    {
        if (!AVrfpInitExclusionsRegexInternal(AVrfProperties.TypeExclusionsRegex[i],
                                              &AVrfpFaultContext.TypeExclusions[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN AVrfpInitIncludeRegex(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING pattern;

    RtlInitUnicodeString(&pattern, AVrfProperties.IncludeRegex);

    if (pattern.Length)
    {
        status = Pcre2Compile(&AVrfpFaultContext.IncludeRegex, &pattern);
        if (!NT_SUCCESS(status))
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "regex failed to compile (0x%08x)",
                         status);

            __debugbreak();
            return FALSE;
        }
    }

    for (ULONG i = 0; i < VFDYNF_FAULT_TYPE_COUNT; i++)
    {
        RtlInitUnicodeString(&pattern, AVrfProperties.TypeIncludeRegex[i]);

        if (!pattern.Length)
        {
            continue;
        }

        status = Pcre2Compile(&AVrfpFaultContext.TypeIncludeRegex[i], &pattern);
        if (!NT_SUCCESS(status))
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "regex failed to compile (0x%08x)",
                         status);

            __debugbreak();
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN AVrfpInitRegex(
    VOID
    )
{
    AVRF_ASSERT(!AVrfpFaultContext.RegexInitialized);

    if (!AVrfpInitIncludeRegex())
    {
        return FALSE;
    }

    if (!AVrfpInitExclusionsRegex())
    {
        return FALSE;
    }

    AVrfpFaultContext.RegexInitialized = TRUE;

    return TRUE;
}

BOOLEAN AVrfpHasAnyExclusionExpressions(
    _In_ ULONG FaultType
    )
{
    if ((AVrfProperties.ExclusionsRegex[0]) != L'\0' ||
        (AVrfProperties.TypeExclusionsRegex[AVrfpFaultTypeIndex(FaultType)] != L'\0'))
    {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN AVrfpIsStackOverriddenByRegex(
    _In_ PUNICODE_STRING StackSymbols,
    _In_ ULONG FaultType
    )
{
    PVFDYNF_EXCLUSION_REGEX typeExclusions;

    AVRF_ASSERT(AVrfpFaultContext.RegexInitialized);

    for (ULONG i = 0; i < AVrfpFaultContext.Exclusions.Count; i++)
    {
        if (Pcre2Match(AVrfpFaultContext.Exclusions.Regex[i], StackSymbols))
        {
            return TRUE;
        }
    }

    typeExclusions = &AVrfpFaultContext.TypeExclusions[AVrfpFaultTypeIndex(FaultType)];
    for (ULONG i = 0; i < typeExclusions->Count; i++)
    {
        if (Pcre2Match(typeExclusions->Regex[i], StackSymbols))
        {
            return TRUE;
        }
    }

    return FALSE;
}

_Function_class_(AVRF_MODULE_ENUM_CALLBACK)
BOOLEAN NTAPI AVrfpFaultModuleEnumCallback(
    _In_ PAVRF_MODULE_ENTRY Module,
    _In_ PVOID Context
    )
{
    PVFDYNF_FAULT_ENUM_MODULES_CONTEXT context;

    context = Context;

    if ((context->CallerAddress >= Module->BaseAddress) &&
        (context->CallerAddress < Module->EndAddress))
    {
        if (AVrfpFaultContext.IncludeRegex)
        {
            if (Pcre2Match(AVrfpFaultContext.IncludeRegex, &Module->BaseName))
            {
                context->Result = TRUE;
                return TRUE;
            }
        }

        if (context->Regex)
        {
            if (Pcre2Match(context->Regex, &Module->BaseName))
            {
                context->Result = TRUE;
                return TRUE;
            }
        }

        return TRUE;
    }

    return FALSE;
}

BOOLEAN AVrfIsCallerIncluded(
    _In_ ULONG FaultType,
    _In_opt_ _Maybenull_ PVOID CallerAddress
    )
{
    VFDYNF_FAULT_ENUM_MODULES_CONTEXT context;

    if (!AVrfpFaultContext.Initialized)
    {
        return FALSE;
    }

    if (!CallerAddress)
    {
        return FALSE;
    }

    AVRF_ASSERT(AVrfpFaultContext.RegexInitialized);

    context.Regex = AVrfpFaultContext.TypeIncludeRegex[AVrfpFaultTypeIndex(FaultType)];

    if (!AVrfpFaultContext.IncludeRegex && !context.Regex)
    {
        return TRUE;
    }

    context.Result = FALSE;

    AVrfEnumLoadedModules(AVrfpFaultModuleEnumCallback, &context);

    return context.Result;
}

VOID AVrfDisableCurrentThreadFaultInjection(
    VOID
    )
{
    AVrfEnterCriticalSection(&AVrfpFaultContext.CriticalSection);
}

VOID AVrfEnableCurrentThreadFaultInjection(
    VOID
    )
{
    //
    // Could use TLS for this, but we're already preventing fault injection
    // where we don't want it with the critical section, so hijack it instead.
    //
#pragma prefast(suppress : 26110)
    AVrfLeaveCriticalSection(&AVrfpFaultContext.CriticalSection);
}

BOOLEAN AVrfpShouldFaultInjectCached(
    _In_ ULONG FaultType,
    _In_ ULONG StackHash,
    _Inout_ PBOOLEAN FaultInject
    )
{
    BOOLEAN result;
    PAVRF_STACK_ENTRY stackEntry;

    result = FALSE;

    AVrfEnterCriticalSection(&AVrfpFaultContext.CriticalSection);

    if (AVrfpFaultContext.CriticalSection.RecursionCount > 1)
    {
        //
        // Do not fault inject if we're recursing on this lock.
        //
        *FaultInject = FALSE;
        result = TRUE;
        goto Exit;
    }

    //
    // Check if we should reset the cache based on the fault period.
    //
    if (AVrfProperties.DynamicFaultPeroid)
    {
        if (!AVrfpFaultContext.LastClear)
        {
            AVrfpFaultContext.LastClear = NtGetTickCount64();
        }
        else if ((AVrfpFaultContext.LastClear + AVrfProperties.DynamicFaultPeroid)
                 <= NtGetTickCount64())
        {
            AVrfpFaultContext.LastClear = NtGetTickCount64();
            AVrfClearStackTable(&AVrfpFaultContext.StackTable);
            goto Exit;
        }
    }

    stackEntry = AVrfLookupStackEntry(&AVrfpFaultContext.StackTable,
                                      StackHash);
    if (!stackEntry || (stackEntry->Hash != StackHash))
    {
        goto Exit;
    }

    //
    // We already evaluated this stack.
    // 1. it's excluded
    // 2. we should inject a fault of an unseen type
    // 3. we already injected the fault type and shouldn't
    //
    if (stackEntry->Excluded)
    {
        *FaultInject = FALSE;
    }
    else if (!BooleanFlagOn(stackEntry->FaultMask, FaultType))
    {
        SetFlag(stackEntry->FaultMask, FaultType);
        *FaultInject = TRUE;
    }
    else
    {
        *FaultInject = FALSE;
    }

    result = TRUE;

Exit:

    AVrfLeaveCriticalSection(&AVrfpFaultContext.CriticalSection);

    return result;
}

VOID AVrfpCacheFaultInjectResult(
    _In_ ULONG FaultType,
    _In_ ULONG StackHash
    )
{
    PAVRF_STACK_ENTRY stackEntry;

    AVrfEnterCriticalSection(&AVrfpFaultContext.CriticalSection);

    stackEntry = AVrfLookupStackEntry(&AVrfpFaultContext.StackTable,
                                      StackHash);
    if (!stackEntry || (stackEntry->Hash != StackHash))
    {
        //
        // Track the new stack entry.
        //
        stackEntry = AVrfInsertStackEntry(&AVrfpFaultContext.StackTable,
                                          stackEntry,
                                          StackHash);
        if (!stackEntry)
        {
            AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to insert new stack entry");

            goto Exit;
        }
    }

    if (FaultType)
    {
        SetFlag(stackEntry->FaultMask, FaultType);
    }
    else
    {
        stackEntry->Excluded = TRUE;
    }

Exit:

    AVrfLeaveCriticalSection(&AVrfpFaultContext.CriticalSection);
}

BOOLEAN AVrfShouldFaultInject(
    _In_ ULONG FaultType,
    _In_opt_ _Maybenull_ PVOID CallerAddress
    )
{
    BOOLEAN result;
    NTSTATUS status;
    PVFDYNF_FAULT_COUNT faultCount;
    ULONG stackHash;
    PVOID frames[250];
    USHORT count;
    PUNICODE_STRING stackSymbols;

    result = FALSE;
    faultCount = NULL;

    if (!AVrfpFaultContext.Initialized)
    {
        goto Exit;
    }

    if (!CallerAddress)
    {
        goto Exit;
    }

    if (!BooleanFlagOn(AVrfProperties.EnableFaultMask, FaultType))
    {
        //
        // Fault type is not enabled.
        //
        goto Exit;
    }

    if (AvrfIsSymProviderThread())
    {
        goto Exit;
    }

    if (!AVrfProperties.EnableFaultsInLdrPath &&
        RtlGetCriticalSectionRecursionCount(NtCurrentPeb()->LoaderLock))
    {
        goto Exit;
    }

    if (!AVrfIsCallerIncluded(FaultType, CallerAddress))
    {
        goto Exit;
    }

    if (!VerifierShouldFaultInject(AVrfpFaultTypeClass(FaultType), CallerAddress))
    {
        goto Exit;
    }

    //
    // After VerifierShouldFaultInject is called verifier has updated its
    // internal tracking that will inject a fault here (see: !avrf -flt).
    // But since we might override that decision, usually due to user defined
    // exclusions, we track our own fault counters when exiting this function.
    //
    faultCount = &AVrfpFaultContext.TypeCount[AVrfpFaultTypeIndex(FaultType)];

    count = RtlCaptureStackBackTrace(1, ARRAYSIZE(frames), frames, &stackHash);

    if (AVrfpShouldFaultInjectCached(FaultType, stackHash, &result))
    {
        goto Exit;
    }

    if (!AVrfpHasAnyExclusionExpressions(FaultType))
    {
        //
        // There are no exclusion expressions, skip the work below.
        //
        AVrfpCacheFaultInjectResult(FaultType, stackHash);
        result = TRUE;
        goto Exit;
    }

    //
    // Classify the stack. Check for overrides by symbols/etc. We build a
    // complete string representation of the stack enabling the regex to span
    // multiple frames. This is the easiest way to enable an author of
    // overrides to write expressions for an entire stack.
    //

    status = AVrfSymGetSymbols(frames,
                               count,
                               &stackSymbols,
                               &AVrfpFaultContext.SymTimeout);
    if (status == STATUS_DEVICE_NOT_READY)
    {
        //
        // Expected when the symbol provider is not yet fully initialized.
        //
        goto Exit;
    }
    if (status != STATUS_SUCCESS)
    {
        //
        // Usually STATUS_TIMEOUT. Symbol resolution might be contending with
        // the loader or generally could not respond in within the time limit.
        //
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "AVrfSymGetSymbol failed (0x%08x)",
                     status);

        goto Exit;
    }

    if (AVrfpIsStackOverriddenByRegex(stackSymbols, FaultType))
    {
        AVrfpCacheFaultInjectResult(FALSE, stackHash);
    }
    else
    {
        //
        // New entry to inject a fault for. Track that we've done so.
        //
        AVrfpCacheFaultInjectResult(FaultType, stackHash);
        result = TRUE;
    }

    AVrfSymFreeSymbols(stackSymbols);

Exit:

    if (faultCount)
    {
        InterlockedIncrement(result ? &faultCount->True : &faultCount->False);
    }

    return result;
}

VOID AVrfpFaultSetRangeForType(
    _In_ ULONG FaultType
    )
{
    //
    // We ask for everything and handle excluding ranges ourself.
    //
    VerifierEnableFaultInjectionTargetRange(AVrfpFaultTypeClass(FaultType),
                                            NULL,
                                            Add2Ptr(NULL, MAXULONG_PTR));
}

VOID AVrfpFaultSetProbabilityForType(
    _In_ ULONG FaultType
    )
{
    VerifierSetFaultInjectionProbability(AVrfpFaultTypeClass(FaultType),
                                         AVrfProperties.FaultProbability);
}

BOOLEAN AVrfFaultProcessAttach(
    VOID
    )
{
    ULONG err;

    if (AVrfpFaultContext.Initialized)
    {
        return TRUE;
    }

    AVrfInitializeStackTable(&AVrfpFaultContext.StackTable);

    if (!AVrfpInitRegex())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL,
                    "failed to initialize exclusions regex");

        __debugbreak();
        return FALSE;
    }

    err = VerifierRegisterFaultInjectProvider(VFDYNF_FAULT_TYPE_COUNT,
                                              &AVrfpFaultContext.TypeBase);
    if (err != ERROR_SUCCESS)
    {
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "failed to register fault injection provider (%lu)",
                     err);

        return FALSE;
    }

    if (AVrfProperties.GracePeriod)
    {
        VerifierSuspendFaultInjection(AVrfProperties.GracePeriod);
    }

    //
    // We ask for everything and handle excluding ranges ourself.
    //
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_WAIT);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_HEAP);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_VMEM);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_REG);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_FILE);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_EVENT);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_SECTION);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_OLE);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_INPAGE);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_FUZZ_REG);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_FUZZ_FILE);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_FUZZ_MMAP);
    AVrfpFaultSetRangeForType(VFDYNF_FAULT_TYPE_FUZZ_NET);

    //
    // By default the system doesn't rely on probability for fault injection.
    // However, there are properties to set the probability and seed if desired.
    //
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_WAIT);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_HEAP);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_VMEM);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_REG);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_FILE);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_EVENT);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_SECTION);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_OLE);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_INPAGE);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_FUZZ_REG);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_FUZZ_FILE);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_FUZZ_MMAP);
    AVrfpFaultSetProbabilityForType(VFDYNF_FAULT_TYPE_FUZZ_NET);

    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_WAIT), L"Wait APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_HEAP), L"Heap APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_VMEM), L"Virtual Memory APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_REG), L"Registry APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_FILE), L"File APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_EVENT), L"Event APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_SECTION), L"Section APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_OLE), L"OLE String APIs");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_INPAGE), L"Section In-Page");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_FUZZ_REG), L"Fuzz Registry");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_FUZZ_FILE), L"Fuzz File");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_FUZZ_MMAP), L"Fuzz Section Map");
    VerifierSetAPIClassName(AVrfpFaultTypeClass(VFDYNF_FAULT_TYPE_FUZZ_NET), L"Fuzz Network");

    if (!AVrfProperties.FaultSeed)
    {
        ULONG seed;
        ULONG rand;

        seed = HandleToULong(NtCurrentThreadId()) ^ NtGetTickCount();
        rand = RtlRandomEx(&seed);

        AVrfDbgPrint(DPFLTR_INFO_LEVEL,
                     "generated and using random fault injection seed %lu",
                     rand);

        VerifierSetFaultInjectionSeed(rand);
    }
    else
    {
        VerifierSetFaultInjectionSeed(AVrfProperties.FaultSeed);
    }

    AVrfInitializeCriticalSection(&AVrfpFaultContext.CriticalSection);

    AVrfDbgPuts(DPFLTR_INFO_LEVEL, "dynamic fault injection initialized");

    AVrfpFaultContext.Initialized = TRUE;
    return TRUE;
}

VOID AVrfFaultProcessDetach(
    VOID
    )
{
    if (AVrfpFaultContext.Initialized)
    {
        return;
    }

    AVrfpFaultContext.Initialized = FALSE;

    AVrfDeleteCriticalSection(&AVrfpFaultContext.CriticalSection);

    if (AVrfpFaultContext.Exclusions.Regex)
    {
        for (ULONG i = 0; i < AVrfpFaultContext.Exclusions.Count; i++)
        {
            if (AVrfpFaultContext.Exclusions.Regex[i])
            {
                Pcre2Close(AVrfpFaultContext.Exclusions.Regex[i]);
            }
        }

        RtlFreeHeap(RtlProcessHeap(), 0, AVrfpFaultContext.Exclusions.Regex);

        AVrfpFaultContext.Exclusions.Regex = NULL;
        AVrfpFaultContext.Exclusions.Count = 0;
    }

    for (ULONG i = 0; i < VFDYNF_FAULT_TYPE_COUNT; i++)
    {
        PVFDYNF_EXCLUSION_REGEX entry;

        entry = &AVrfpFaultContext.TypeExclusions[i];

        if (entry->Regex)
        {
            for (ULONG j = 0; j < entry->Count; j++)
            {
                if (entry->Regex[j])
                {
                    Pcre2Close(&entry->Regex[j]);
                }
            }

            RtlFreeHeap(RtlProcessHeap(), 0, entry->Regex);
            entry->Regex = NULL;
            entry->Count = 0;
        }
    }

    Pcre2Close(AVrfpFaultContext.IncludeRegex);

    for (ULONG i = 0; i < VFDYNF_FAULT_TYPE_COUNT; i++)
    {
        if (AVrfpFaultContext.TypeIncludeRegex[i])
        {
            Pcre2Close(AVrfpFaultContext.TypeIncludeRegex[i]);
            AVrfpFaultContext.TypeIncludeRegex[i] = NULL;
        }
    }

    AVrfFreeStackTable(&AVrfpFaultContext.StackTable);
}
