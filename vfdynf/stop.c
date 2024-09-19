/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

typedef struct _VFDYNF_VERIFIER_STOP_MODULE_ENUM_CONTEXT
{
    PVOID CallerAddress;
    BOOLEAN Result;
} VFDYNF_VERIFIER_STOP_MODULE_ENUM_CONTEXT, *PVFDYNF_VERIFIER_STOP_MODULE_ENUM_CONTEXT;

static PCRE2_HANDLE AVrfpStopRegex = NULL;

_Function_class_(AVRF_MODULE_ENUM_CALLBACK)
BOOLEAN NTAPI AVrfpVerifierStopModuleEnumCallback(
    _In_ PAVRF_MODULE_ENTRY Module,
    _In_ PVOID Context
    )
{
    PVFDYNF_VERIFIER_STOP_MODULE_ENUM_CONTEXT context;

    context = Context;

    if ((context->CallerAddress >= Module->BaseAddress) &&
        (context->CallerAddress < Module->EndAddress))
    {
        if (AVrfpStopRegex)
        {
            context->Result = Pcre2Match(AVrfpStopRegex, &Module->BaseName);
        }
        else
        {
            context->Result = TRUE;
        }

        return TRUE;
    }

    if (!AVrfpStopRegex)
    {
        //
        // Only check the primary module if a regex wasn't provided.
        //
        return TRUE;
    }

    return FALSE;
}

BOOLEAN AVrfShouldVerifierStop(
    _In_opt_ _Maybenull_ PVOID CallerAddress
    )
{
    VFDYNF_VERIFIER_STOP_MODULE_ENUM_CONTEXT context;

    context.CallerAddress = CallerAddress;
    context.Result = FALSE;

    AVrfEnumLoadedModules(AVrfpVerifierStopModuleEnumCallback, &context);

    return context.Result;
}

BOOLEAN AVrfStopProcessAttach(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING pattern;

    RtlInitUnicodeString(&pattern, AVrfProperties.StopRegex);

    if (!pattern.Length)
    {
        return TRUE;
    }

    status = Pcre2Compile(&AVrfpStopRegex, &pattern);
    if (!NT_SUCCESS(status))
    {
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "regex failed to compile (0x%08x)",
                     status);

        __debugbreak();
        return FALSE;
    }

    return TRUE;
}

VOID AVrfStopProcessDetach(
    VOID
    )
{
    if (AVrfpStopRegex)
    {
        Pcre2Close(AVrfpStopRegex);
        AVrfpStopRegex = NULL;
    }
}
