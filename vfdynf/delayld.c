/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#define VFDYNF_DELAYLD_PRIVATE
#include <delayld.h>

typedef struct _AVRF_DELAY_LOAD_ENTRY
{
    ANSI_STRING ProcedureName;
    PVOID* Store;
} AVRF_DELAY_LOAD_ENTRY, *PAVRF_DELAY_LOAD_ENTRY;

typedef struct _AVRF_DELAY_LOAD_DLL
{
    UNICODE_STRING DllName;
    PAVRF_DELAY_LOAD_ENTRY Entries;
    PVOID BaseAddress;
    PVOID EndAddress;
} AVRF_DELAY_LOAD_DLL, *PAVRF_DELAY_LOAD_DLL;

#define AVRF_DELAY_LOAD(x) { RTL_CONSTANT_STRING(#x), (PVOID*)&Delay_##x }

static AVRF_DELAY_LOAD_ENTRY AVrfpDelayLoadDbgHelp[] =
{
    AVRF_DELAY_LOAD(SymRegisterCallbackW64),
    AVRF_DELAY_LOAD(SymCleanup),
    AVRF_DELAY_LOAD(SymGetOptions),
    AVRF_DELAY_LOAD(SymRefreshModuleList),
    AVRF_DELAY_LOAD(SymFromAddrW),
    AVRF_DELAY_LOAD(SymInitializeW),
    AVRF_DELAY_LOAD(SymSetOptions),
    { RTL_CONSTANT_STRING(""), NULL }
};

static AVRF_DELAY_LOAD_ENTRY AVrfpDelayLoadBCrypt[] =
{
    AVRF_DELAY_LOAD(BCryptGenRandom),
    { RTL_CONSTANT_STRING(""), NULL }
};

static AVRF_DELAY_LOAD_DLL AVrfpDelayLoadDlls[] =
{
    { RTL_CONSTANT_STRING(L"dbghelp.dll"), AVrfpDelayLoadDbgHelp, NULL, NULL },
    { RTL_CONSTANT_STRING(L"bcrypt.dll"),  AVrfpDelayLoadBCrypt, NULL, NULL },
    { RTL_CONSTANT_STRING(L""), NULL, NULL, NULL }
};

static AVRF_RUN_ONCE AVrfpDelayLoadOnce = AVRF_RUN_ONCE_INIT;

_Function_class_(AVRF_RUN_ONCE_ROUTINE)
BOOLEAN NTAPI AVrfpDelayLoad(
    VOID
    )
{
    NTSTATUS status;
    PVOID ldrCookie;
    ULONG ldrDisp;
    PLIST_ENTRY modList;

    status = STATUS_SUCCESS;

    for (PAVRF_DELAY_LOAD_DLL dllEntry = AVrfpDelayLoadDlls;
         dllEntry->Entries;
         dllEntry = dllEntry + 1)
    {
        PVOID baseAddress;

        status = LdrLoadDll(NULL, NULL, &dllEntry->DllName, &baseAddress);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed to delay load %wZ (0x%08x)\n",
                       &dllEntry->DllName,
                       status);
            goto Exit;
        }

        dllEntry->BaseAddress = baseAddress;

        for (PAVRF_DELAY_LOAD_ENTRY entry = dllEntry->Entries;
             entry->Store;
             entry = entry + 1)
        {
            status = LdrGetProcedureAddress(baseAddress,
                                            &entry->ProcedureName,
                                            0,
                                            entry->Store);
            if (!NT_SUCCESS(status))
            {
                DbgPrintEx(DPFLTR_VERIFIER_ID,
                           DPFLTR_ERROR_LEVEL,
                           "AVRF: failed to delay load %wZ!%wZ (0x%08x)\n",
                           &dllEntry->DllName,
                           &entry->ProcedureName,
                           status);
                __debugbreak();
                goto Exit;
            }
        }
    }

    status = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
                               &ldrDisp,
                               &ldrCookie);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: failed to acquire loader lock (0x%08x)!\n",
                   status);

        __debugbreak();
        goto Exit;
    }
    if (ldrDisp != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: loader lock is busy!\n");

        status = STATUS_LOCK_NOT_GRANTED;
        __debugbreak();
        goto Exit;
    }

    modList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;

    for (PAVRF_DELAY_LOAD_DLL dllEntry = AVrfpDelayLoadDlls;
         dllEntry->Entries;
         dllEntry = dllEntry + 1)
    {
        for (PLIST_ENTRY entry = modList->Flink;
             entry != modList;
             entry = entry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY item;

            item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (item->DllBase == dllEntry->BaseAddress)
            {
                dllEntry->EndAddress = Add2Ptr(item->DllBase, item->SizeOfImage);
                break;
            }
        }
    }

    LdrUnlockLoaderLock(0, ldrCookie);

Exit:

    return NT_SUCCESS(status);
}

_Must_inspect_result_
BOOLEAN AVrfDelayLoadInitOnce(
    VOID
    )
{
    return AVrfRunOnce(&AVrfpDelayLoadOnce, AVrfpDelayLoad, TRUE);
}

_Must_inspect_result_
BOOLEAN AVrfInDelayLoadDll(
    _In_opt_ _Maybenull_ PVOID Address
    )
{
    for (PAVRF_DELAY_LOAD_DLL dllEntry = AVrfpDelayLoadDlls;
         dllEntry->Entries;
         dllEntry = dllEntry + 1)
    {
        if ((Address >= dllEntry->BaseAddress) &&
            (Address < dllEntry->EndAddress))
        {
            return TRUE;
        }
    }

    return FALSE;
}
