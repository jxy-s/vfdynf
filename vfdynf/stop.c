/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

static PCRE2_CONTEXT StopRegex = { NULL, NULL };

BOOLEAN AVrfShouldVerifierStop(
    _In_opt_ _Maybenull_ PVOID CallerAddress
)
{
    BOOLEAN result;
    NTSTATUS status;
    PVOID ldrCookie;
    ULONG ldrDisp;
    PLIST_ENTRY modList;

    status = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
                               &ldrDisp,
                               &ldrCookie);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: failed to acquire loader lock (0x%08x)!\n",
                   status);

        return FALSE;
    }

    if (ldrDisp != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: loader lock is busy!\n");

        return FALSE;
    }

    result = FALSE;
    modList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY entry = modList->Flink;
         entry != modList;
         entry = entry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY item;
        PVOID end;

        item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        end = Add2Ptr(item->DllBase, item->SizeOfImage);

        if ((CallerAddress >= item->DllBase) && (CallerAddress < end))
        {
            if (StopRegex.Code)
            {
                result = Pcre2Match(&StopRegex, &item->BaseDllName);
            }
            else
            {
                result = TRUE;
            }

            break;
        }

        if (!StopRegex.Code)
        {
            //
            // Only check the primary module if a regex wasn't provided.
            //
            break;
        }
    }

    LdrUnlockLoaderLock(0, ldrCookie);

    return result;
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

    status = Pcre2Compile(&StopRegex, &pattern);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed processing regex! (0x%08x)\n",
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
    if (StopRegex.Code)
    {
        Pcre2Close(&StopRegex);
    }
}
