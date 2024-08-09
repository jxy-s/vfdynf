/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

static BOOLEAN AVrfpLoadedAsVerifier = FALSE;

VFDYNF_PROPERTIES AVrfProperties =
{
    .GracePeriod = 5000,
    .SymbolSearchPath = { L'\0' },
    .ExclusionsRegex = { L'\0' },
    .DynamicFaultPeroid = 30000,
    .EnableFaultMask = VFDYNF_FAULT_DEFAULT_MASK,
    .FaultProbability = 1000000,
    .FaultSeed = 0,
    .FuzzCorruptionBlocks = 100,
    .FuzzChaosProbability = 250000,
    .FuzzSizeTruncateProbability = 250000,
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
    { 0 }
};

VOID NTAPI AVrfpDllLoadCallback(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);
}

VOID NTAPI AVrfpDllUnlodCallback(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);
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
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: expected descriptor output parameter is null");
        return FALSE;
    }

    *desc = &AVrfpProviderDescriptor;

    status = VerifierRegisterProvider(Module, &AVrfpProviderDescriptor);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: provider registration failed (0x%08x)",
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
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: layer registration failed (%lu)",
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

    if (!AVrfHookProcessAttach())
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to finalize hooks");
        __debugbreak();
        return FALSE;
    }

    if (!AVrfFuzzProcessAttach())
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to setup fuzzing");
        __debugbreak();
        return FALSE;
    }

    if (!AVrfExceptProcessAttach())
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to set exception handler");
        __debugbreak();
        return FALSE;
    }

    if (!AVrfFaultProcessAttach())
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to setup fault injection");
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