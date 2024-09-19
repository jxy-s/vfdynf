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
    AVRF_DELAY_LOAD(SymLoadModuleExW),
    AVRF_DELAY_LOAD(SymUnloadModule64),
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

_Function_class_(AVRF_MODULE_ENUM_CALLBACK)
BOOLEAN NTAPI AVrfpDelayLoadModuleEnumCallback(
    _In_ PAVRF_MODULE_ENTRY Module,
    _In_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    for (PAVRF_DELAY_LOAD_DLL dllEntry = AVrfpDelayLoadDlls;
         dllEntry->Entries;
         dllEntry = dllEntry + 1)
    {
        if (Module->BaseAddress == dllEntry->BaseAddress)
        {
            dllEntry->EndAddress = Module->EndAddress;
            return FALSE;
        }
    }

    return FALSE;
}

_Function_class_(AVRF_RUN_ONCE_ROUTINE)
BOOLEAN NTAPI AVrfpDelayLoad(
    VOID
    )
{
    NTSTATUS status;

    status = STATUS_SUCCESS;

    for (PAVRF_DELAY_LOAD_DLL dllEntry = AVrfpDelayLoadDlls;
         dllEntry->Entries;
         dllEntry = dllEntry + 1)
    {
        PVOID baseAddress;

        status = LdrLoadDll(NULL, NULL, &dllEntry->DllName, &baseAddress);
        if (!NT_SUCCESS(status))
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "failed to delay load %wZ (0x%08x)",
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
                AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                             "failed to delay load %wZ!%hZ (0x%08x)",
                             &dllEntry->DllName,
                             &entry->ProcedureName,
                             status);

                __debugbreak();
                goto Exit;
            }
        }
    }

    AVrfEnumLoadedModules(AVrfpDelayLoadModuleEnumCallback, NULL);

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
