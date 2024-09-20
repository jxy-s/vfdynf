/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

static BOOLEAN AVrfpLoadedAsVerifier = FALSE;
static BOOLEAN AVrfpModuleListInitialized = FALSE;
static RTL_SRWLOCK AVrfpModuleListLock = RTL_SRWLOCK_INIT;
static LIST_ENTRY AVrfpModulesList = { 0 };

VFDYNF_PROPERTIES AVrfProperties =
{
    .GracePeriod = 5000,
    .SymbolSearchPath = { L'\0' },
    .StopRegex = { L'\0' },
    .IncludeRegex = { L'\0' },
    .ExclusionsRegex = { L'\0' },
    .DynamicFaultPeroid = 30000,
    .EnableFaultMask = VFDYNF_FAULT_DEFAULT_MASK,
    .FaultProbability = 1000000,
    .FaultSeed = 0,
    .FuzzCorruptionBlocks = 100,
    .FuzzChaosProbability = 250000,
    .FuzzSizeTruncateProbability = 250000,
    .HeapReasonableAllocLimit = (1 << 30), // 1 GiB
    .EnableFaultsInLdrPath = FALSE,
    .TypeIncludeRegex = { 0 },
    .TypeExclusionsRegex = { 0 },
};

static AVRF_PROPERTY_DESCRIPTOR AVrfpPropertyDescriptors[] =
{
    {
        AVRF_PROPERTY_DWORD,
        L"GracePeriod",
        &AVrfProperties.GracePeriod,
        sizeof(AVrfProperties.GracePeriod),
        L"Delays fault injection until after this period, in milliseconds.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"SymbolSearchPath",
        &AVrfProperties.SymbolSearchPath,
        sizeof(AVrfProperties.SymbolSearchPath),
        L"Symbol search path used for dynamic fault injection and applying "
        L"exclusions.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"IncludeRegex",
        &AVrfProperties.IncludeRegex,
        sizeof(AVrfProperties.IncludeRegex),
        L"Includes fault injection for the immediate calling module when this "
        L"regular expression matches the module name. When not provided all "
        L"modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"ExclusionsRegex",
        &AVrfProperties.ExclusionsRegex,
        sizeof(AVrfProperties.ExclusionsRegex),
        L"Excludes stack from fault injection when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_DWORD,
        L"DynamicFaultPeroid",
        &AVrfProperties.DynamicFaultPeroid,
        sizeof(AVrfProperties.DynamicFaultPeroid),
        L"Clears dynamic stack fault injection tracking on this period, in "
        L"milliseconds, zero does not clear tracking.",
        NULL
    },
    {
        AVRF_PROPERTY_QWORD,
        L"EnableFaultMask",
        &AVrfProperties.EnableFaultMask,
        sizeof(AVrfProperties.EnableFaultMask),
        L"Mask of which fault types are enabled. Bit 1=Wait, 2=Heap, 3=VMem, "
        L"4=Reg, 5=File, 6=Event, 7=Section, 8=Ole, 9=InPage, 10=FuzzReg, "
        L"11=FuzzFile, 12=FuzzMMap.",
        NULL
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FaultProbability",
        &AVrfProperties.FaultProbability,
        sizeof(AVrfProperties.FaultProbability),
        L"Probability that a fault will be injected (0 - 1000000).",
        NULL
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FaultSeed",
        &AVrfProperties.FaultSeed,
        sizeof(AVrfProperties.FaultSeed),
        L"Seed used for fault randomization. A value of zero will generate a "
        L"random seed.",
        NULL
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FuzzCorruptionBlocks",
        &AVrfProperties.FuzzCorruptionBlocks,
        sizeof(AVrfProperties.FuzzCorruptionBlocks),
        L"Maximum number of blocks to corrupt when fuzzing. Larger numbers "
        L"will impact performance, fuzzing logic will randomly loop between "
        L"one and this maximum to apply corruption techniques on buffers.",
        NULL
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FuzzChaosProbability",
        &AVrfProperties.FuzzChaosProbability,
        sizeof(AVrfProperties.FuzzChaosProbability),
        L"The probability (0 - 1000000) a corruption block will overwrite a "
        L"portion of buffer with random data. Otherwise various corruption "
        L"techniques are applied to the buffer in a less chaotic manner.",
        NULL
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FuzzSizeTruncateProbability",
        &AVrfProperties.FuzzSizeTruncateProbability,
        sizeof(AVrfProperties.FuzzSizeTruncateProbability),
        L"The probability (0 - 1000000) that data lengths will be truncated "
        L"to a random value below the actual length of the output data.",
        NULL
    },
    {
        AVRF_PROPERTY_QWORD,
        L"HeapReasonableAllocLimit",
        &AVrfProperties.HeapReasonableAllocLimit,
        sizeof(AVrfProperties.HeapReasonableAllocLimit),
        L"Limit which is considered a reasonable single heap allocation. If "
        L"the size a single heap allocation exceeds this limit a verifier "
        L"stop is raised.",
        NULL
    },
    {
        AVRF_PROPERTY_BOOLEAN,
        L"EnableFaultsInLdrPath",
        &AVrfProperties.EnableFaultsInLdrPath,
        sizeof(AVrfProperties.EnableFaultsInLdrPath),
        L"Enables fault injection when in the loader path. When disabled the "
        L"fault logic will check if the current thread is inside of the loader "
        L"path and skip fault injection if it is.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"StopRegex",
        &AVrfProperties.StopRegex,
        sizeof(AVrfProperties.StopRegex),
        L"Regular expression to check against the immediate caller module name "
        L"when a verifier stop is about to be raised. If the module does not "
        L"match this regular expression the verifier stop does not occur. "
        L"Defaults to matching only the application module.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"WaitIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_WAIT],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_WAIT]),
        L"Includes wait fault injection for the immediate calling module when "
        L"this regular expression matches the module name. When not provided "
        L"all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"HeapIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_HEAP],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_HEAP]),
        L"Includes heap fault injection for the immediate calling module when "
        L"this regular expression matches the module name. When not provided "
        L"all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"VMemIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_VMEM],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_VMEM]),
        L"Includes virtual memory fault injection for the immediate calling "
        L"module when this regular expression matches the module name. When "
        L"not provided all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"RegIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_REG],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_REG]),
        L"Includes registry fault injection for the immediate calling module "
        L"when this regular expression matches the module name.When not "
        L"provided all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"FileIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FILE],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FILE]),
        L"Includes file fault injection for the immediate calling module when "
        L"this regular expression matches the module name.When not provided "
        L"all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"EventIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_EVENT],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_EVENT]),
        L"Includes event fault injection for the immediate calling module when "
        L"this regular expression matches the module name.When not provided "
        L"all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"SectionIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_SECTION],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_SECTION]),
        L"Includes section fault injection for the immediate calling module "
        L"when this regular expression matches the module name.When not "
        L"provided all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"OleIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_OLE],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_OLE]),
        L"Includes OLE fault injection for the immediate calling module when "
        L"this regular expression matches the module name.When not provided "
        L"all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"InPageIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_INPAGE],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_INPAGE]),
        L"Includes in-page fault injection for the immediate calling module "
        L"when this regular expression matches the module name.When not "
        L"provided all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"FuzzRegIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_REG],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_REG]),
        L"Includes registry fuzzing for the immediate calling module when this "
        L"regular expression matches the module name.When not provided all "
        L"modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"FuzzFileIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_FILE],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_FILE]),
        L"Includes file fuzzing for the immediate calling module when this "
        L"regular expression matches the module name.When not provided all "
        L"modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"FuzzMMapIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_MMAP],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_MMAP]),
        L"Includes section map fuzzing for the immediate calling module when "
        L"this regular expression matches the module name.When not provided "
        L"all modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_SZ,
        L"FuzzNetIncludeRegex",
        &AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET],
        sizeof(AVrfProperties.TypeIncludeRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET]),
        L"Includes network fuzzing for the immediate calling module when this "
        L"regular expression matches the module name.When not provided all "
        L"modules are included.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"WaitExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_WAIT],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_WAIT]),
        L"Excludes stack from wait fault injection when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"HeapExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_HEAP],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_HEAP]),
        L"Excludes stack from heap fault injection when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"VMemExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_VMEM],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_VMEM]),
        L"Excludes stack from virtual memory fault injection when one of "
        L"these regular expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"RegExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_REG],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_REG]),
        L"Excludes stack from registry fault injection when one of these "
        L"regular expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"FileExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FILE],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FILE]),
        L"Excludes stack from file fault injection when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"EventExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_EVENT],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_EVENT]),
        L"Excludes stack from event fault injection when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"SectionExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_SECTION],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_SECTION]),
        L"Excludes stack from section fault injection when one of these "
        L"regular expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"OleExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_OLE],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_OLE]),
        L"Excludes stack from OLE fault injection when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"InPageExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_INPAGE],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_INPAGE]),
        L"Excludes stack from section in-page fault injection when one of "
        L"these regular expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"FuzzRegExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_REG],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_REG]),
        L"Excludes stack from registry fuzzing when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"FuzzFileExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_FILE],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_FILE]),
        L"Excludes stack from file fuzzing when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"FuzzMMapExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_MMAP],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_MMAP]),
        L"Excludes stack from section map fuzzing when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"FuzzNetExclusionsRegex",
        &AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET],
        sizeof(AVrfProperties.TypeExclusionsRegex[VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET]),
        L"Excludes stack from network fuzzing when one of these regular "
        L"expression matches the stack.",
        NULL
    },
    { AVRF_PROPERTY_NONE, NULL, NULL, 0, NULL, NULL }
};

static AVRF_BREAK_DESCRIPTOR AVrfpBreakDescriptors[] =
{
    {
        VFDYNF_CODE_DEPRECATED_FUNCTION,
        AVRF_BREAK_ACTIVE | AVRF_BREAK_BREAKPOINT | AVRF_BREAK_LOG_TO_FILE | AVRF_BREAK_LOG_STACK_TRACE,
        AVRF_BREAK_WARNING,
        0,
        NULL, IDS_DEPRECATED_FUNCTION_MESSAGE,
        NULL, IDS_NOT_USED,
        NULL, IDS_NOT_USED,
        NULL, IDS_NOT_USED,
        NULL, IDS_NOT_USED,
        NULL, IDS_DEPRECATED_FUNCTION_FORMAT,
        NULL, IDS_DEPRECATED_FUNCTION_DESCRIPTION,
        NULL
    },
    {
        VFDYNF_CODE_HEAP_ALLOC_LIMIT,
        AVRF_BREAK_ACTIVE | AVRF_BREAK_BREAKPOINT | AVRF_BREAK_LOG_TO_FILE | AVRF_BREAK_LOG_STACK_TRACE,
        AVRF_BREAK_WARNING,
        0,
        NULL, IDS_HEAP_ALLOC_LIMIT_MESSAGE,
        NULL, IDS_HEAP_ALLOC_LIMIT_PARAM_1,
        NULL, IDS_NOT_USED,
        NULL, IDS_NOT_USED,
        NULL, IDS_NOT_USED,
        NULL, IDS_EMPTY,
        NULL, IDS_HEAP_ALLOC_LIMIT_DESCRIPTION,
        NULL
    },
    { 0 }
};

#define AVRF_RUN_ONCE_NOT_RUN      0
#define AVRF_RUN_ONCE_INITIALIZING 1
#define AVRF_RUN_ONCE_COMPLETED    2
#define AVRF_RUN_ONCE_FAILED       3

typedef struct _AVRF_RUN_ONCE_ASYNC_CONTEXT
{
    PAVRF_RUN_ONCE Once;
    PAVRF_RUN_ONCE_ROUTINE Routine;
} AVRF_RUN_ONCE_ASYNC_CONTEXT, *PAVRF_RUN_ONCE_ASYNC_CONTEXT;

NTSTATUS NTAPI AVrfpAsyncRunOnceRoutine(
    _In_ PVOID ThreadParameter
    )
{
    PAVRF_RUN_ONCE_ASYNC_CONTEXT context;
    AVRF_RUN_ONCE res;

    context = ThreadParameter;

    res = context->Routine() ? AVRF_RUN_ONCE_COMPLETED : AVRF_RUN_ONCE_FAILED;

    InterlockedExchange(context->Once, res);

    RtlFreeHeap(RtlProcessHeap(), 0, context);

    return STATUS_SUCCESS;
}

VOID AVrfpAsyncRunOnce(
    _In_ PAVRF_RUN_ONCE Once,
    _In_ PAVRF_RUN_ONCE_ROUTINE Routine
    )
{
    NTSTATUS status;
    PAVRF_RUN_ONCE_ASYNC_CONTEXT context;

    context = RtlAllocateHeap(RtlProcessHeap(),
                              0,
                              sizeof(AVRF_RUN_ONCE_ASYNC_CONTEXT));
    if (!context)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    context->Once = Once;
    context->Routine = Routine;

    status = RtlCreateUserThread(NtCurrentProcess(),
                                 NULL,
                                 FALSE,
                                 0,
                                 0,
                                 0,
                                 AVrfpAsyncRunOnceRoutine,
                                 context,
                                 NULL,
                                 NULL);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    context = NULL;

Exit:

    if (context)
    {
        RtlFreeHeap(RtlProcessHeap(), 0, context);
    }

    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(Once, AVRF_RUN_ONCE_FAILED);
    }
}

BOOLEAN AVrfRunOnce(
    _Inout_ PAVRF_RUN_ONCE Once,
    _In_ PAVRF_RUN_ONCE_ROUTINE Routine,
    _In_ BOOLEAN Async
    )
{
    AVRF_RUN_ONCE res;

    res = InterlockedCompareExchange(Once,
                                     AVRF_RUN_ONCE_INITIALIZING,
                                     AVRF_RUN_ONCE_NOT_RUN);

    if (res == AVRF_RUN_ONCE_NOT_RUN)
    {
        if (Async)
        {
            AVrfpAsyncRunOnce(Once, Routine);
            res = AVRF_RUN_ONCE_INITIALIZING;
        }
        else
        {
            res = Routine() ? AVRF_RUN_ONCE_COMPLETED : AVRF_RUN_ONCE_FAILED;
        }

        InterlockedExchange(Once, res);
    }

    return (res == AVRF_RUN_ONCE_COMPLETED);
}

BOOLEAN AVrfEnumLoadedModules(
    _In_ PAVRF_MODULE_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    BOOLEAN result;

    result = FALSE;

    RtlAcquireSRWLockShared(&AVrfpModuleListLock);

    if (!AVrfpModuleListInitialized)
    {
        goto Exit;
    }

    for (PLIST_ENTRY entry = AVrfpModulesList.Flink;
         entry != &AVrfpModulesList;
         entry = entry->Flink)
    {
        PAVRF_MODULE_ENTRY module;

        module = CONTAINING_RECORD(entry, AVRF_MODULE_ENTRY, Entry);

        if (Callback(module, Context))
        {
            result = TRUE;
            break;
        }
    }

Exit:

    RtlReleaseSRWLockShared(&AVrfpModuleListLock);

    return result;
}

VOID AVrfpRefreshLoadedModuleList(
    VOID
    )
{
    ULONG ldrDisp;
    PVOID ldrCookie;
    LIST_ENTRY newList;
    PLIST_ENTRY listEntry;
    PAVRF_MODULE_ENTRY module;
    LIST_ENTRY oldList;

    InitializeListHead(&newList);

    LdrLockLoaderLock(0, &ldrDisp, &ldrCookie);

    listEntry = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY entry = listEntry->Flink;
         entry != listEntry;
         entry = entry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY ldr;
        ULONG size;

        ldr = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        size = sizeof(AVRF_MODULE_ENTRY);
        size += ldr->FullDllName.Length + sizeof(WCHAR);
        size += ldr->BaseDllName.Length + sizeof(WCHAR);

        module = RtlAllocateHeap(RtlProcessHeap(), 0, size);
        if (!module)
        {
            AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to allocate module entry");

            __debugbreak();
            continue;
        }

        RtlZeroMemory(module, size);

        module->BaseAddress = ldr->DllBase;
        module->EndAddress = Add2Ptr(ldr->DllBase, ldr->SizeOfImage);

        module->FullName.Length = 0;
        module->FullName.MaximumLength = ldr->FullDllName.Length + sizeof(WCHAR);
        module->FullName.Buffer = (PWCH)module->Buffer;

        module->BaseName.Length = 0;
        module->BaseName.MaximumLength = ldr->BaseDllName.Length + sizeof(WCHAR);
        module->BaseName.Buffer = (PWCH)&module->Buffer[module->FullName.MaximumLength];

        RtlCopyUnicodeString(&module->FullName, &ldr->FullDllName);
        RtlCopyUnicodeString(&module->BaseName, &ldr->BaseDllName);

        InsertTailList(&newList, &module->Entry);
    }

    if (ldrDisp == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
    {
        LdrUnlockLoaderLock(0, ldrCookie);
    }

    InitializeListHead(&oldList);

    RtlAcquireSRWLockExclusive(&AVrfpModuleListLock);

    if (!IsListEmpty(&AVrfpModulesList))
    {
        listEntry = AVrfpModulesList.Flink;
        RemoveEntryList(&AVrfpModulesList);
        InitializeListHead(&AVrfpModulesList);
        AppendTailList(&oldList, listEntry);
    }

    if (!IsListEmpty(&newList))
    {
        listEntry = newList.Flink;
        RemoveEntryList(&newList);
        InitializeListHead(&newList);
        AppendTailList(&AVrfpModulesList, listEntry);
    }

    RtlReleaseSRWLockExclusive(&AVrfpModuleListLock);

    while (!IsListEmpty(&oldList))
    {
        module = CONTAINING_RECORD(RemoveHeadList(&oldList),
                                   AVRF_MODULE_ENTRY,
                                   Entry);
        RtlFreeHeap(RtlProcessHeap(), 0, module);
    }
}

VOID AVrfpInitModulesList(
    VOID
    )
{
    InitializeListHead(&AVrfpModulesList);
    AVrfpRefreshLoadedModuleList();
    AVrfpModuleListInitialized = TRUE;
}

VOID AVrfpDeleteModuleList(
    VOID
    )
{
    if (!AVrfpModuleListInitialized)
    {
        return;
    }

    while (!IsListEmpty(&AVrfpModulesList))
    {
        PAVRF_MODULE_ENTRY entry;

        entry = CONTAINING_RECORD(RemoveTailList(&AVrfpModulesList),
                                  AVRF_MODULE_ENTRY,
                                  Entry);

        RtlFreeHeap(RtlProcessHeap(), 0, entry);
    }
}

VOID AVrfpTrackModule(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize
    )
{
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(DllSize);

    if (AVrfpModuleListInitialized)
    {
        AVrfpRefreshLoadedModuleList();
    }
}

VOID AVrfpUnTrackModule(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize
    )
{
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(DllSize);

    if (AVrfpModuleListInitialized)
    {
        AVrfpRefreshLoadedModuleList();
    }
}

VOID NTAPI AVrfpDllLoadCallback(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    )
{
    //
    // N.B. This routine is NOT called with the loader lock held.
    //
    UNREFERENCED_PARAMETER(Reserved);

    AVrfpTrackModule(DllName, DllBase, DllSize);
    AVrfSymDllLoad(DllName, DllBase, DllSize);
    AVrfLinkHooks();
}

VOID NTAPI AVrfpDllUnlodCallback(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    )
{
    //
    // N.B. This routine is called with the loader lock held.
    //
    UNREFERENCED_PARAMETER(Reserved);

    AVrfpUnTrackModule(DllName, DllBase, DllSize);
    AVrfSymDllUnload(DllName, DllBase, DllSize);
}

VOID NTAPI AVrfpNtdllHeapFreeCallback(
    _In_ PVOID AllocationBase,
    _In_ SIZE_T AllocationSize
    )
{
    UNREFERENCED_PARAMETER(AllocationBase);
    UNREFERENCED_PARAMETER(AllocationSize);
}

static RTL_VERIFIER_PROVIDER_DESCRIPTOR AVrfpProviderDescriptor =
{
    sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR),
    AVrfDllDescriptors,
    AVrfpDllLoadCallback,
    AVrfpDllUnlodCallback,
    NULL,
    0,
    0,
    NULL,
    NULL,
    NULL,
    AVrfpNtdllHeapFreeCallback
};

ULONG NTAPI AVrfpPropertyCallback(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Property
    )
{
    UNREFERENCED_PARAMETER(Property);
    return ERROR_SUCCESS;
}

ULONG NTAPI AVrfpValidateCallback(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Property
    )
{
    UNREFERENCED_PARAMETER(Property);
    return ERROR_SUCCESS;
}

AVRF_LAYER_DESCRIPTOR AVrfLayerDescriptor =
{
    &AVrfpProviderDescriptor,
    L"{d41d391a-d897-4956-953f-ed66b3861169}",
    L"DynFault",
    1,
    0,
    AVrfpBreakDescriptors,
    AVrfpPropertyDescriptors,
    NULL,
    L"Unique-stack based systematic fault injection to simulate low resource scenarios.",
    L"Dynamic Fault Injection",
    0,
    0,
    NULL,
    AVrfpPropertyCallback,
    AVrfpValidateCallback
};

BOOLEAN AVrfpProviderProcessVerifier(
    _In_ HMODULE Module,
    _In_opt_ PVOID Reserved
    )
{
    NTSTATUS status;
    PRTL_VERIFIER_PROVIDER_DESCRIPTOR* desc;

    desc = (PRTL_VERIFIER_PROVIDER_DESCRIPTOR*)Reserved;
    if (!desc)
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL,
                    "expected descriptor output parameter is null");

        return FALSE;
    }

    *desc = &AVrfpProviderDescriptor;

    status = VerifierRegisterProvider(Module, &AVrfpProviderDescriptor);
    if (!NT_SUCCESS(status))
    {
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "provider registration failed (0x%08x)",
                     status);

        return FALSE;
    }

    AVrfpLoadedAsVerifier = TRUE;
    return TRUE;
}

BOOLEAN AVrfpProviderProcessAttach(
    _In_ HMODULE Module
    )
{
    ULONG err;

    err = VerifierRegisterLayerEx(Module,
                                  &AVrfLayerDescriptor,
                                  0);
    if (err != ERROR_SUCCESS)
    {
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "layer registration failed (%lu)",
                     err);

        return FALSE;
    }

    //
    // Verifier will load us to get the descriptors. Verifier does this to
    // display options for users. Unless invoked with DLL_PROCESS_ATTACH we
    // must return true.
    //
    if (!AVrfpLoadedAsVerifier)
    {
        return TRUE;
    }

    AVrfpInitModulesList();

    if (!AVrfLinkHooks())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to link hooks");

        __debugbreak();
        return FALSE;
    }

    if (!AVrfSymProcessAttach())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to setup symbol provider");

        __debugbreak();
        return FALSE;
    }

    if (!AVrfStopProcessAttach())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to setup stop handling");

        __debugbreak();
        return FALSE;
    }

    if (!AVrfFuzzProcessAttach())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to setup fuzzing");

        __debugbreak();
        return FALSE;
    }

    if (!AVrfExceptProcessAttach())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to set exception handler");

        __debugbreak();
        return FALSE;
    }

    if (!AVrfFaultProcessAttach())
    {
        AVrfDbgPuts(DPFLTR_ERROR_LEVEL, "failed to setup fault injection");

        __debugbreak();
        return FALSE;
    }

    return TRUE;
}

VOID AVrfpProviderProcessDetach(
    _In_ HMODULE Module
    )
{
    AVrfFaultProcessDetach();
    AVrfExceptProcessDetach();
    AVrfFuzzProcessDetach();
    AVrfStopProcessDetach();
    AVrfSymProcessDetach();
    AVrfpDeleteModuleList();

    VerifierUnregisterLayer(Module, &AVrfLayerDescriptor);
}

BOOL WINAPI DllMain(
    _In_ HMODULE Module,
    _In_ ULONG Reason,
    _In_ PVOID Reserved
    )
{
    switch (Reason)
    {
        case DLL_PROCESS_VERIFIER:
        {
            if (!AVrfpProviderProcessVerifier(Module, Reserved))
            {
                return FALSE;
            }
            break;
        }
        case DLL_PROCESS_ATTACH:
        {
            __security_init_cookie();

            if (!AVrfpProviderProcessAttach(Module))
            {
                return FALSE;
            }
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            AVrfpProviderProcessDetach(Module);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        {
            break;
        }
    }

    return TRUE;
}