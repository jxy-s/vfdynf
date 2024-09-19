/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <delayld.h>

typedef struct _VFDYNF_FAULT_ENUM_MODULES_CONTEXT
{
    PVOID CallerAddress;
    PPCRE2_CONTEXT TypeInclude;
    BOOLEAN Result;
} VFDYNF_FAULT_ENUM_MODULES_CONTEXT, *PVFDYNF_FAULT_ENUM_MODULES_CONTEXT;

typedef struct _VFDYNF_EXCLUSION_REGEX
{
    ULONG Count;
    PPCRE2_CONTEXT Regex;
} VFDYNF_EXCLUSION_REGEX, *PVFDYNF_EXCLUSION_REGEX;

typedef struct _VFDYNF_FAULT_COUNT
{
    volatile LONG False;
    volatile LONG True;
} VFDYNF_FAULT_COUNT, *PVFDYNF_FAULT_COUNT;

typedef struct _VFDYNF_FAULT_CONTEXT
{
    BOOLEAN Initialized;
    BOOLEAN SymInitialized;
    ULONG TypeBase;
    RTL_CRITICAL_SECTION CriticalSection;
    ULONG64 LastClear;
    AVRF_STACK_TABLE StackTable;
    BOOLEAN RegexInitialized;
    PCRE2_CONTEXT Include;
    VFDYNF_EXCLUSION_REGEX Exclusions;
    VFDYNF_FAULT_COUNT TypeCount[VFDYNF_FAULT_TYPE_COUNT];
    PCRE2_CONTEXT TypeInclude[VFDYNF_FAULT_TYPE_COUNT];
    VFDYNF_EXCLUSION_REGEX TypeExclusions[VFDYNF_FAULT_TYPE_COUNT];
    BYTE SymInfoBuffer[sizeof(SYMBOL_INFOW) + ((MAX_SYM_NAME + 1) * sizeof(WCHAR))];
    WCHAR SymbolBuffer[MAX_SYM_NAME + 1 + MAX_PATH];
    WCHAR StackSymbolBuffer[UNICODE_STRING_MAX_CHARS];
} VFDYNF_FAULT_CONTEXT, *PVFDYNF_FAULT_CONTEXT;

static AVRF_RUN_ONCE AVrfpFaultRunOnce = AVRF_RUN_ONCE_INIT;

static VFDYNF_FAULT_CONTEXT AVrfpFaultContext =
{
    .Initialized = FALSE,
    .SymInitialized = FALSE,
    .TypeBase = ULONG_MAX,
    .CriticalSection = { 0 },
    .LastClear = 0,
    .StackTable = { 0 },
    .RegexInitialized = FALSE,
    .Include = { 0 },
    .Exclusions = { 0 },
    .TypeCount = { 0 },
    .TypeInclude = { 0 },
    .TypeExclusions = { 0 },
    .SymInfoBuffer = { 0 },
    .SymbolBuffer = { 0 },
    .StackSymbolBuffer = { 0 },
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

BOOL CALLBACK AVrfpSymbolRegsteredCallback(
    _In_ HANDLE hProcess,
    _In_ ULONG ActionCode,
    _In_opt_ ULONG64 CallbackData,
    _In_opt_ ULONG64 UserContext
    )
{
    PIMAGEHLP_DEFERRED_SYMBOL_LOADW64 info;

    UNREFERENCED_PARAMETER(hProcess);
    UNREFERENCED_PARAMETER(UserContext);

    info = (PIMAGEHLP_DEFERRED_SYMBOL_LOADW64)(ULONG_PTR)CallbackData;

    switch (ActionCode)
    {
        case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE:
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_INFO_LEVEL,
                       "AVRF: loaded symbols %ls\n",
                       info->FileName);
            break;
        }
        case CBA_DEFERRED_SYMBOL_LOAD_FAILURE:
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed to loaded symbols %ls\n",
                       info->FileName);
            break;
        }
        case CBA_DEFERRED_SYMBOL_LOAD_PARTIAL:
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: partially loaded symbols %ls\n",
                       info->FileName);
            break;
        }
        case CBA_SYMBOLS_UNLOADED:
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_INFO_LEVEL,
                       "AVRF: unloaded symbols %ls\n",
                       info->FileName);
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}

_Function_class_(AVRF_RUN_ONCE_ROUTINE)
BOOLEAN NTAPI AVrfpFaultRunOnceRoutine(
    VOID
    )
{
    if (AVrfProperties.SymbolSearchPath[0] == L'\0')
    {
        if (!Delay_SymInitializeW(NtCurrentProcess(), NULL, FALSE))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed to initialize symbols (%lu)\n",
                       NtCurrentTeb()->LastErrorValue);
            return FALSE;
        }
    }
    else
    {
        if (!Delay_SymInitializeW(NtCurrentProcess(),
                                  AVrfProperties.SymbolSearchPath,
                                  FALSE))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed to initialize symbols (%lu)\n",
                       NtCurrentTeb()->LastErrorValue);
            return FALSE;
        }
    }

    AVrfpFaultContext.SymInitialized = TRUE;

    Delay_SymSetOptions(Delay_SymGetOptions() | SYMOPT_UNDNAME);
    Delay_SymRegisterCallbackW64(NtCurrentProcess(), AVrfpSymbolRegsteredCallback, 0);
    Delay_SymRefreshModuleList(NtCurrentProcess());

    return TRUE;
}

BOOLEAN AVrfpFaultDelayInitOnce(
    VOID
    )
{
    if (!AVrfDelayLoadInitOnce())
    {
        return FALSE;
    }

    return AVrfRunOnce(&AVrfpFaultRunOnce, AVrfpFaultRunOnceRoutine, FALSE);
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
                                       count * sizeof(PCRE2_CONTEXT));
    if (!Exclusion->Regex)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to allocate exclusion regex!\n");
        __debugbreak();
        return FALSE;
    }

    offset = 0;
    count = 0;
    for (;;)
    {
        NTSTATUS status;
        UNICODE_STRING pattern;
        PCRE2_CONTEXT pcre2;

        RtlInitUnicodeString(&pattern, &Pattern[offset]);
        if (!pattern.Length)
        {
            break;
        }

        status = Pcre2Compile(&pcre2, &pattern);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed processing regex! (0x%08x)\n",
                       status);
            __debugbreak();
            return FALSE;
        }

        AVRF_ASSERT(count < Exclusion->Count);

        Exclusion->Regex[count++] = pcre2;

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
        status = Pcre2Compile(&AVrfpFaultContext.Include, &pattern);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed processing regex! (0x%08x)\n",
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

        status = Pcre2Compile(&AVrfpFaultContext.TypeInclude[i], &pattern);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed processing regex! (0x%08x)\n",
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
        if (Pcre2Match(&AVrfpFaultContext.Exclusions.Regex[i], StackSymbols))
        {
            return TRUE;
        }
    }

    typeExclusions = &AVrfpFaultContext.TypeExclusions[AVrfpFaultTypeIndex(FaultType)];
    for (ULONG i = 0; i < typeExclusions->Count; i++)
    {
        if (Pcre2Match(&typeExclusions->Regex[i], StackSymbols))
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
        if (AVrfpFaultContext.Include.Code)
        {
            if (Pcre2Match(AVrfpFaultContext.Include.Code, &Module->BaseName))
            {
                context->Result = TRUE;
                return TRUE;
            }
        }

        if (context->TypeInclude)
        {
            if (Pcre2Match(context->TypeInclude, &Module->BaseName))
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
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: fault injection not yet initialized\n");

        return FALSE;
    }

    if (!CallerAddress)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: caller address is null\n");

        return FALSE;
    }

    AVRF_ASSERT(AVrfpFaultContext.RegexInitialized);

    context.TypeInclude = &AVrfpFaultContext.TypeInclude[AVrfpFaultTypeIndex(FaultType)];

    if (!AVrfpFaultContext.Include.Code && !context.TypeInclude->Code)
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

BOOLEAN AVrfShouldFaultInject(
    _In_ ULONG FaultType,
    _In_opt_ _Maybenull_ PVOID CallerAddress
    )
{
    BOOLEAN result;
    BOOLEAN releaseLock;
    PVFDYNF_FAULT_COUNT faultCount;
    ULONG lastErrorValue;
    NTSTATUS lastStatusValue;
    ULONG hash;
    PVOID frames[250];
    USHORT count;
    PAVRF_STACK_ENTRY stackEntry;
    UNICODE_STRING stackSymbols;

    result = FALSE;
    releaseLock = FALSE;
    faultCount = NULL;

    //
    // This function can be called from a hook and could change the last error
    // and status values. Save them to be restored when we exit this function.
    //
    lastErrorValue = NtCurrentTeb()->LastErrorValue;
    lastStatusValue = NtCurrentTeb()->LastStatusValue;

    if (!AVrfpFaultContext.Initialized)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: fault injection not yet initialized\n");

        goto Exit;
    }

    if (!CallerAddress)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: caller address is null\n");

        goto Exit;
    }

    if (!BooleanFlagOn(AVrfProperties.EnableFaultMask, FaultType))
    {
        //
        // Fault type is not enabled.
        //
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

    if (!AVrfpFaultDelayInitOnce())
    {
        goto Exit;
    }

    if (AVrfInDelayLoadDll(CallerAddress))
    {
        goto Exit;
    }

    if (!AVrfIsCallerIncluded(FaultType, CallerAddress))
    {
        goto Exit;
    }

    count = RtlCaptureStackBackTrace(1, ARRAYSIZE(frames), frames, &hash);

    AVrfEnterCriticalSection(&AVrfpFaultContext.CriticalSection);
    releaseLock = TRUE;

    if (AVrfpFaultContext.CriticalSection.RecursionCount > 1)
    {
        //
        // Do not fault inject if we're back in this routine. This can happen
        // while we're resolving symbols.
        //
        // N.B. It is important to check this before potentially resetting
        // the table based on fault period below. Else the caller that landed
        // us back here would have the table reset out from underneath it.
        //
        goto Exit;
    }

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
        }
    }

    stackEntry = AVrfLookupStackEntry(&AVrfpFaultContext.StackTable, hash);
    if (stackEntry && (stackEntry->Hash == hash))
    {
        //
        // We already evaluated this stack.
        // 1. it's excluded
        // 2. we should inject a fault of an unseen type
        // 3. we already injected a fault and shouldn't
        //

        if (stackEntry->Excluded)
        {
            goto Exit;
        }

        if (!BooleanFlagOn(stackEntry->FaultMask, FaultType))
        {
            SetFlag(stackEntry->FaultMask, FaultType);
            result = TRUE;
            goto Exit;
        }

        //
        // We've already injected a fault for this stack and fault type.
        //
        goto Exit;
    }

    //
    // We haven't yet evaluated this stack, do so now.
    //

    stackEntry = AVrfInsertStackEntry(&AVrfpFaultContext.StackTable,
                                      stackEntry,
                                      hash);
    if (!stackEntry)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to insert new stack entry!\n");

        goto Exit;
    }

    if (!AVrfpHasAnyExclusionExpressions(FaultType))
    {
        //
        // There are no exclusion expressions, skip the work below.
        //
        SetFlag(stackEntry->FaultMask, FaultType);
        result = TRUE;
        goto Exit;
    }

    DbgPrintEx(DPFLTR_VERIFIER_ID,
               DPFLTR_MASK | 0x10,
               "AVRF: Cid %04x.%04x stack frame count: %hu\n",
               HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess),
               HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
               count);

    //
    // Classify the stack. Check for overrides by symbols/etc. We build a
    // complete string representation of the stack enabling the regex to span
    // multiple frames. This is the easiest way to enable an author of
    // overrides to write expressions for an entire stack.
    //

    //
    // N.B. This processing is always done under the critical section so it's
    // safe for us to reuse the preallocated buffer in this path. We use a
    // preallocated buffer that will satisfy the maximum possible length of
    // a UNICODE_STRING.
    //
    stackSymbols.Length = 0;
    stackSymbols.MaximumLength = sizeof(AVrfpFaultContext.StackSymbolBuffer);
    stackSymbols.Buffer = AVrfpFaultContext.StackSymbolBuffer;

    for (WORD i = 0; i < count; i++)
    {
        NTSTATUS status;
        PSYMBOL_INFOW info;
        ULONG64 disp;
        PVOID ldrCookie;
        ULONG ldrDisp;
        PLDR_DATA_TABLE_ENTRY data;
        PLIST_ENTRY modList;
        UNICODE_STRING symbol;

        info = (PSYMBOL_INFOW)AVrfpFaultContext.SymInfoBuffer;

        RtlZeroMemory(info, sizeof(*info));
        info->SizeOfStruct = sizeof(SYMBOL_INFOW);
        info->MaxNameLen = MAX_SYM_NAME;

        if (!Delay_SymFromAddrW(NtCurrentProcess(),
                                (ULONG64)frames[i],
                                &disp,
                                info))
        {
            //
            // Refresh the module list and try again.
            //
            Delay_SymRefreshModuleList(NtCurrentProcess());

            if (!Delay_SymFromAddrW(NtCurrentProcess(),
                                    (ULONG64)frames[i],
                                    &disp,
                                    info))
            {
                DbgPrintEx(DPFLTR_VERIFIER_ID,
                           DPFLTR_WARNING_LEVEL,
                           "AVRF: failed to get symbol info %p (%lu)\n",
                           frames[i],
                           NtCurrentTeb()->LastErrorValue);

                //
                // Zero the structure, we'll handle this below. The analysis
                // will be given a frame with only a module name and no symbol.
                // e.g. "ntdll.dll!"
                //
                RtlZeroMemory(info, sizeof(*info));
            }
        }

        //
        // To minimize the tracking we have to do and since we're already
        // injected into the process, we're going to just use the loader
        // module list to identify the module of the symbol. First, try
        // to get the loader lock - if we can't we just concede and get out
        // of the way of the system - we won't inject a fault.
        //
        status = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
                                   &ldrDisp,
                                   &ldrCookie);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: failed to acquire loader lock (0x%08x)!\n",
                       status);

            AVrfRemoveStackEntry(&AVrfpFaultContext.StackTable, stackEntry);

            goto Exit;
        }
        if (ldrDisp != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: loader lock is busy!\n");

            AVrfRemoveStackEntry(&AVrfpFaultContext.StackTable, stackEntry);

            goto Exit;
        }

        data = NULL;
        modList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;

        for (PLIST_ENTRY entry = modList->Flink;
             entry != modList;
             entry = entry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY item;

            item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (info->ModBase != 0)
            {
                if (item->DllBase == (PVOID)(ULONG_PTR)info->ModBase)
                {
                    data = item;
                    break;
                }
            }
            else
            {
                PVOID end;

                //
                // Either dbghelp didn't give us a module base or the call to
                // resolve the symbol name failed. Identify the module by the
                // extents.
                //

                end = Add2Ptr(item->DllBase, item->SizeOfImage);
                if ((frames[i] >= item->DllBase) && (frames[i] < end))
                {
                    data = item;
                    break;
                }
            }
        }

        //
        // Build the symbol string.
        //

        symbol.Length = 0;
        symbol.MaximumLength = sizeof(AVrfpFaultContext.SymbolBuffer);
        symbol.Buffer = AVrfpFaultContext.SymbolBuffer;

        if (!data)
        {
            RtlAppendUnicodeToString(&symbol, L"(null)");
        }
        else
        {
            RtlAppendUnicodeStringToString(&symbol, &data->BaseDllName);
        }

        //
        // We're done with the loader lock.
        //
        LdrUnlockLoaderLock(0, ldrCookie);

        RtlAppendUnicodeToString(&symbol, L"!");
        RtlAppendUnicodeToString(&symbol, info->Name);

        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_MASK | 0x10,
                   "AVRF: %wZ\n",
                   &symbol);

        //
        // If we fail here it means we've run out of the maximum Unicode string
        // length which is innately impossible to extend further. Rather than
        // consider this a failure, we'll just stop appending symbols, debug
        // print that an error occurred, and break out to classify the stack
        // that we do have.
        //

        status = RtlAppendUnicodeStringToString(&stackSymbols, &symbol);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: failed to append symbol to stack string (0x%08x)!\n",
                       status);
            break;
        }

        status = RtlAppendUnicodeToString(&stackSymbols, L"\n");
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: failed to append new line to stack string (0x%08x)!\n",
                       status);
            break;
        }
    }

    if (stackSymbols.Length >= sizeof(WCHAR))
    {
        //
        // Pop the last new line.
        //
        stackSymbols.Length -= sizeof(WCHAR);

        if (AVrfpIsStackOverriddenByRegex(&stackSymbols, FaultType))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_INFO_LEVEL,
                       "AVRF: stack excluded by regular expression\n");

            //
            // Cache the decision for this stack hash.
            //
            stackEntry->Excluded = TRUE;
            goto Exit;
        }
    }

    //
    // New entry that we need to inject a fault for. Track that we've done so.
    //
    SetFlag(stackEntry->FaultMask, FaultType);
    result = TRUE;

Exit:

    if (releaseLock)
    {
        AVrfLeaveCriticalSection(&AVrfpFaultContext.CriticalSection);
    }

    if (faultCount)
    {
        InterlockedIncrement(result ? &faultCount->True : &faultCount->False);
    }

    NtCurrentTeb()->LastErrorValue = lastErrorValue;
    NtCurrentTeb()->LastStatusValue = lastStatusValue;

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
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to initialized exclusions regex!\n");
        __debugbreak();
        return FALSE;
    }

    err = VerifierRegisterFaultInjectProvider(VFDYNF_FAULT_TYPE_COUNT,
                                              &AVrfpFaultContext.TypeBase);
    if (err != ERROR_SUCCESS)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to register fault injection provider (%lu)\n",
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

        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_INFO_LEVEL,
                   "AVRF: generated and using random fault injection seed %lu\n",
                   rand);

        VerifierSetFaultInjectionSeed(rand);
    }
    else
    {
        VerifierSetFaultInjectionSeed(AVrfProperties.FaultSeed);
    }

    AVrfInitializeCriticalSection(&AVrfpFaultContext.CriticalSection);

    DbgPrintEx(DPFLTR_VERIFIER_ID,
               DPFLTR_INFO_LEVEL,
               "AVRF: dynamic fault injection initialized\n");

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
            Pcre2Close(&AVrfpFaultContext.Exclusions.Regex[i]);
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
                Pcre2Close(&entry->Regex[j]);
            }

            RtlFreeHeap(RtlProcessHeap(), 0, entry->Regex);
            entry->Regex = NULL;
            entry->Count = 0;
        }
    }

    Pcre2Close(&AVrfpFaultContext.Include);

    for (ULONG i = 0; i < VFDYNF_FAULT_TYPE_COUNT; i++)
    {
        Pcre2Close(&AVrfpFaultContext.TypeInclude[i]);
    }

    AVrfFreeStackTable(&AVrfpFaultContext.StackTable);

    if (AVrfpFaultContext.SymInitialized)
    {
        Delay_SymCleanup(NtCurrentProcess());
    }
}
