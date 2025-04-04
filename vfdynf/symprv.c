/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <delayld.h>
#include <strsafe.h>

typedef union _VFDYNF_SYM_MODULE_ENUM_CONTEXT
{
    struct
    {
        PVOID Frame;
        PUNICODE_STRING Symbol;
    } Sym;

    struct
    {
        PVOID BaseAddress;
        PUNICODE_STRING FullName;
    } DllLoad;
} VFDYNF_SYM_MODULE_ENUM_CONTEXT, *PVFDYNF_SYM_MODULE_ENUM_CONTEXT;

typedef enum _VFDYNF_SYM_REQUEST_TYPE
{
    SymSymbols,
    SymDllLoad,
    SymDllUnload,
} VFDYNF_SYM_REQUEST_TYPE, *PVFDYNF_SYM_REQUEST_TYPE;

typedef struct _VFDYNF_SYM_SYMBOLS
{
    volatile BOOLEAN Abandoned;
    DECLSPEC_ALIGN(16) UNICODE_STRING StackSymbols;
    ULONG FramesCount;
    PVOID Frames[250];
    WCHAR SymbolBuffer[MAX_SYM_NAME + MAX_PATH + 1];
    DECLSPEC_ALIGN(16) WCHAR StackSymbolBuffer[UNICODE_STRING_MAX_CHARS];
} VFDYNF_SYM_SYMBOLS, *PVFDYNF_SYM_SYMBOLS;

typedef struct _VFDYNF_SYM_DLL_LOAD_UNLOAD
{
    PVOID DllBase;
    SIZE_T DllSize;
    WCHAR DllName[MAX_PATH];
} VFDYNF_SYM_DLL_LOAD_UNLOAD, * PVFDYNF_SYM_DLL_LOAD_UNLOAD;

typedef struct _VFDYNF_SYM_REQUEST
{
    volatile LONG RefCount;
    SLIST_ENTRY Entry;
    NTSTATUS Status;
    HANDLE Event;

    VFDYNF_SYM_REQUEST_TYPE Type;

    union
    {
        VFDYNF_SYM_SYMBOLS Symbols;
        VFDYNF_SYM_DLL_LOAD_UNLOAD DllLoad;
        VFDYNF_SYM_DLL_LOAD_UNLOAD DllUnload;
    };
} VFDYNF_SYM_REQUEST, *PVFDYNF_SYM_REQUEST;

typedef struct _VFDYNF_SYMBOL_PROVDER_CONTEXT
{
    BOOLEAN Initialized;
    volatile BOOLEAN SymInitialized;
    volatile BOOLEAN StopWorker;
    CRITICAL_SECTION CriticalSection;
    HANDLE WorkerThreadHandle;
    HANDLE WorkerThreadId;
    volatile HANDLE InitThreadId;
    volatile LONG CurrentAbandoned;
    SLIST_HEADER WorkQueue;
    HANDLE WorkQueueEvent;
    SLIST_HEADER FreeList;
    BYTE SymbolInfoBuffer[sizeof(SYMBOL_INFOW) + ((MAX_SYM_NAME + 1) * sizeof(WCHAR))];
} VFDYNF_SYMBOL_PROVDER_CONTEX, *PVFDYNF_SYMBOL_PROVDER_CONTEXT;

static AVRF_RUN_ONCE AVrfpSymRunOnce = AVRF_RUN_ONCE_INIT;

static VFDYNF_SYMBOL_PROVDER_CONTEX AVrfpSymContext =
{
    .Initialized = FALSE,
    .SymInitialized = FALSE,
    .StopWorker = FALSE,
    .CriticalSection = { 0 },
    .WorkerThreadHandle = NULL,
    .WorkerThreadId = NULL,
    .CurrentAbandoned = 0,
    .InitThreadId = NULL,
    .WorkQueue = { 0 },
    .WorkQueueEvent = { 0 },
    .FreeList = { 0 },
    .SymbolInfoBuffer = { 0 },
};

_Must_inspect_result_
PVFDYNF_SYM_REQUEST AVrfpSymCreateRequest(
    VOID
    )
{
    PVFDYNF_SYM_REQUEST sym;
    PSLIST_ENTRY entry;

    entry = RtlInterlockedPopEntrySList(&AVrfpSymContext.FreeList);
    if (entry)
    {
        sym = CONTAINING_RECORD(entry, VFDYNF_SYM_REQUEST, Entry);
    }
    else
    {
        sym = RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(VFDYNF_SYM_REQUEST));
        if (!sym)
        {
            return NULL;
        }

        RtlZeroMemory(sym, sizeof(VFDYNF_SYM_REQUEST));

        if (!NT_SUCCESS(NtCreateEvent(&sym->Event,
                                      EVENT_ALL_ACCESS,
                                      NULL,
                                      NotificationEvent,
                                      FALSE)))
        {
            RtlFreeHeap(RtlProcessHeap(), 0, sym);
            return NULL;
        }
    }

    InterlockedIncrement(&sym->RefCount);

    return sym;
}

VOID AVrfpSymFreeRequest(
    _In_ PVFDYNF_SYM_REQUEST Sym
    )
{
    if (Sym->Event)
    {
        NtClose(Sym->Event);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, Sym);
}

VOID AVrfpSymReference(
    _In_ PVFDYNF_SYM_REQUEST Sym
    )
{
    InterlockedIncrement(&Sym->RefCount);
}

VOID AVrfpSymDereference(
    _In_ PVFDYNF_SYM_REQUEST Sym
    )
{
    if (!InterlockedDecrement(&Sym->RefCount))
    {
        if (InterlockedExchangeAcquireBoolean(&Sym->Symbols.Abandoned, FALSE))
            InterlockedDecrement((LONG volatile*)&AVrfpSymContext.CurrentAbandoned);

        RtlInterlockedPushEntrySList(&AVrfpSymContext.FreeList, &Sym->Entry);
    }
}

VOID AVrfpSymAbandonSymbolsRequest(
    _Inout_ PVFDYNF_SYM_REQUEST Sym
    )
{
    ULONG abandoned;

    abandoned = (ULONG)InterlockedIncrement(&AVrfpSymContext.CurrentAbandoned);

    WriteReleaseBoolean(&Sym->Symbols.Abandoned, TRUE);

    if (abandoned == AVrfProperties.SymAbandonedThreshold)
    {
        AVrfDbgPrint(DPFLTR_WARNING_LEVEL,
                     "abandoned threshold reached %d",
                     abandoned);
    }
}

BOOL CALLBACK AVrfpSymRegsteredSymbolCallback(
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
            AVrfDbgPrint(DPFLTR_INFO_LEVEL,
                         "loaded symbols %ls",
                         info->FileName);
            break;
        }
        case CBA_DEFERRED_SYMBOL_LOAD_FAILURE:
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "failed to loaded symbols %ls",
                         info->FileName);
            break;
        }
        case CBA_DEFERRED_SYMBOL_LOAD_PARTIAL:
        {
            AVrfDbgPrint(DPFLTR_WARNING_LEVEL,
                         "partially loaded symbols %ls",
                         info->FileName);
            break;
        }
        case CBA_SYMBOLS_UNLOADED:
        {
            AVrfDbgPrint(DPFLTR_INFO_LEVEL,
                         "unloaded symbols %ls",
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
BOOLEAN NTAPI AVrfpSymRunOnceRoutine(
    VOID
    )
{
    BOOLEAN result;

    WritePointerRelease(&AVrfpSymContext.InitThreadId, NtCurrentThreadId());

    AVrfEnterCriticalSection(&AVrfpSymContext.CriticalSection);

    if (AVrfProperties.SymbolSearchPath[0] == L'\0')
    {
        if (!Delay_SymInitializeW(NtCurrentProcess(), NULL, FALSE))
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "failed to initialize symbols (%lu)",
                         NtCurrentTeb()->LastErrorValue);

            result = FALSE;
            goto Exit;
        }
    }
    else
    {
        if (!Delay_SymInitializeW(NtCurrentProcess(),
                                  AVrfProperties.SymbolSearchPath,
                                  FALSE))
        {
            AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                         "failed to initialize symbols (%lu)",
                         NtCurrentTeb()->LastErrorValue);

            result = FALSE;
            goto Exit;
        }
    }

    Delay_SymSetOptions(Delay_SymGetOptions() | SYMOPT_UNDNAME);
    Delay_SymRegisterCallbackW64(NtCurrentProcess(),
                                 AVrfpSymRegsteredSymbolCallback,
                                 0);

    WriteReleaseBoolean(&AVrfpSymContext.SymInitialized, TRUE);

    Delay_SymRefreshModuleList(NtCurrentProcess());

    result = TRUE;

Exit:

    AVrfLeaveCriticalSection(&AVrfpSymContext.CriticalSection);

#pragma prefast(suppress : 6387) // SAL is incorrect on WritePointerRelease
    WritePointerRelease(&AVrfpSymContext.InitThreadId, NULL);

    return result;
}

BOOLEAN AVrfpSymDelayInitOnce(
    VOID
    )
{
    if (!AVrfDelayLoadInitOnce())
    {
        return FALSE;
    }

    //
    // N.B. Asynchronous initialization here (Aync = TRUE) is important to
    // avoid contention with the loader.
    //
    // Even though the symbol provider works asynchronously and is capable
    // of timing out symbol requests. If a developer is frequently loading and
    // unloading DLLs immediately during startup, significant contention can
    // occur with dbghelp initialization and the loader draining its work
    // queue. The result of this is many requests timeout, effectively
    // resulting in a "livelock" of the functionality. The asynchronous
    // initialization here gives the loader and dbghelp time to initialize
    // independently before the symbol provider becomes fully operational.
    //
    return AVrfRunOnce(&AVrfpSymRunOnce, AVrfpSymRunOnceRoutine, TRUE);
}

_Function_class_(AVRF_MODULE_ENUM_CALLBACK)
BOOLEAN NTAPI AVrfpSymModuleEnumCallback(
    _In_ PAVRF_MODULE_ENTRY Module,
    _In_ PVOID Context
    )
{
    PVFDYNF_SYM_MODULE_ENUM_CONTEXT context;

    context = Context;

    if ((context->Sym.Frame >= Module->BaseAddress) &&
        (context->Sym.Frame < Module->EndAddress))
    {
        RtlCopyUnicodeString(context->Sym.Symbol, &Module->BaseName);
        return TRUE;
    }

    return FALSE;
}

NTSTATUS AVrfpSymResolveSymbols(
    _In_ PVFDYNF_SYM_SYMBOLS Sym
    )
{
    NTSTATUS status;

    if (!AVrfpSymDelayInitOnce())
    {
        status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }

    Sym->StackSymbols.Length = 0;
    Sym->StackSymbols.MaximumLength = sizeof(Sym->StackSymbolBuffer);
    Sym->StackSymbols.Buffer = Sym->StackSymbolBuffer;

    for (ULONG i = 0; i < Sym->FramesCount; i++)
    {
        PVOID frame;
        PSYMBOL_INFOW info;
        ULONG64 disp;
        UNICODE_STRING symbol;
        VFDYNF_SYM_MODULE_ENUM_CONTEXT context;

        frame = Sym->Frames[i];

        symbol.Length = 0;
        symbol.MaximumLength = sizeof(Sym->SymbolBuffer);
        symbol.Buffer = Sym->SymbolBuffer;

        context.Sym.Frame = frame;
        context.Sym.Symbol = &symbol;

        if (ReadAcquireBoolean(&Sym->Abandoned))
        {
            //
            // The thread waiting on this to complete has timed out and no
            // longer wants a result, stop processing. In situations where
            // the work queue is backing up this helps with recovery.
            //
            status = STATUS_ABANDONED;
            goto Exit;
        }

        if (!AVrfEnumLoadedModules(AVrfpSymModuleEnumCallback, &context))
        {
            RtlAppendUnicodeToString(&symbol, L"(null)");
        }

        RtlAppendUnicodeToString(&symbol, L"!");

        AVrfEnterCriticalSection(&AVrfpSymContext.CriticalSection);

        info = (PSYMBOL_INFOW)AVrfpSymContext.SymbolInfoBuffer;

        RtlZeroMemory(info, sizeof(SYMBOL_INFOW));
        info->SizeOfStruct = sizeof(SYMBOL_INFOW);
        info->MaxNameLen = MAX_SYM_NAME;

        //
        // If this fails the symbol will not be appended to the module. The
        // caller will be given a frame with only a module name: "ntdll.dll!"
        //
        if (Delay_SymFromAddrW(NtCurrentProcess(),
                               (ULONG64)frame,
                               &disp,
                               info))
        {
            RtlAppendUnicodeToString(&symbol, info->Name);
        }

        AVrfLeaveCriticalSection(&AVrfpSymContext.CriticalSection);

        //
        // If we fail here it means we've run out of the maximum Unicode string
        // length which is innately impossible to extend further. Rather than
        // consider this a failure, we'll just stop appending symbols, debug
        // print that an error occurred, and break out to classify the stack
        // that we do have.
        //

        status = RtlAppendUnicodeStringToString(&Sym->StackSymbols, &symbol);
        if (!NT_SUCCESS(status))
        {
            AVrfDbgPrint(DPFLTR_WARNING_LEVEL,
                         "failed to append symbol to stack string (0x%08x)",
                         status);

            status = STATUS_SUCCESS;
            goto Exit;
        }

        status = RtlAppendUnicodeToString(&Sym->StackSymbols, L"\n");
        if (!NT_SUCCESS(status))
        {
            AVrfDbgPrint(DPFLTR_WARNING_LEVEL,
                         "failed to append new line to stack string (0x%08x)",
                         status);

            status = STATUS_SUCCESS;
            goto Exit;
        }
    }

    if (Sym->StackSymbols.Length >= sizeof(WCHAR))
    {
        //
        // Pop the last new line.
        //
        Sym->StackSymbols.Length -= sizeof(WCHAR);
    }

    status = STATUS_SUCCESS;

Exit:

    return status;
}

_Function_class_(AVRF_MODULE_ENUM_CALLBACK)
BOOLEAN NTAPI AVrfpSymDllLoadModuleCallback(
    _In_ PAVRF_MODULE_ENTRY Module,
    _In_ PVOID Context
    )
{
    PVFDYNF_SYM_MODULE_ENUM_CONTEXT context;

    context = Context;

    if (context->DllLoad.BaseAddress == Module->BaseAddress)
    {
        RtlCopyUnicodeString(context->DllLoad.FullName, &Module->FullName);
        return TRUE;
    }

    return FALSE;
}

NTSTATUS AVrfpSymDllLoad(
    _In_ PVFDYNF_SYM_DLL_LOAD_UNLOAD Sym
    )
{
    VFDYNF_SYM_MODULE_ENUM_CONTEXT context;
    WCHAR fullName[MAX_PATH + 1];
    UNICODE_STRING fullNameString;

    if (!ReadAcquireBoolean(&AVrfpSymContext.SymInitialized))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    fullNameString.Length = 0;
    fullNameString.MaximumLength = MAX_PATH * sizeof(WCHAR);
    fullNameString.Buffer = fullName;

    context.DllLoad.BaseAddress = Sym->DllBase;
    context.DllLoad.FullName = &fullNameString;

    if (!AVrfEnumLoadedModules(AVrfpSymDllLoadModuleCallback, &context))
    {
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL, "failed to locate %ls", Sym->DllName);

        return STATUS_NOT_FOUND;
    }

    fullName[fullNameString.Length / sizeof(WCHAR)] = UNICODE_NULL;

    AVrfEnterCriticalSection(&AVrfpSymContext.CriticalSection);

    if (!Delay_SymLoadModuleExW(NtCurrentProcess(),
                                NULL,
                                fullName,
                                Sym->DllName,
                                (ULONG64)Sym->DllBase,
                                (ULONG)Sym->DllSize,
                                NULL,
                                0) &&
        NtCurrentTeb()->LastErrorValue)
    {
        AVrfDbgPrint(DPFLTR_WARNING_LEVEL,
                     "SymLoadModuleExW failed %ls (%lu)",
                     Sym->DllName,
                     NtCurrentTeb()->LastErrorValue);
    }

    AVrfLeaveCriticalSection(&AVrfpSymContext.CriticalSection);

    return STATUS_SUCCESS;
}

NTSTATUS AVrfpSymDllUnload(
    _In_ PVFDYNF_SYM_DLL_LOAD_UNLOAD Sym
    )
{
    if (!ReadAcquireBoolean(&AVrfpSymContext.SymInitialized))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    AVrfEnterCriticalSection(&AVrfpSymContext.CriticalSection);

    Delay_SymUnloadModule64(NtCurrentProcess(), (ULONG64)Sym->DllBase);

    AVrfLeaveCriticalSection(&AVrfpSymContext.CriticalSection);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI AVrfpSymWorker(
    _In_ PVOID ThreadParameter
    )
{
    KPRIORITY threadPriority;

    UNREFERENCED_PARAMETER(ThreadParameter);

    //
    // This thread has the potential to block all other threads in the process
    // waiting on it to complete resolving symbols. It must take priority.
    //
    threadPriority = THREAD_PRIORITY_HIGHEST;

    NtSetInformationThread(NtCurrentThread(),
                           ThreadBasePriority,
                           &threadPriority,
                           sizeof(KPRIORITY));

    while (!ReadAcquireBoolean(&AVrfpSymContext.StopWorker))
    {
        PSLIST_ENTRY work;

        work = RtlInterlockedFlushSList(&AVrfpSymContext.WorkQueue);
        if (!work)
        {
            NtWaitForSingleObject(AVrfpSymContext.WorkQueueEvent, FALSE, NULL);
            continue;
        }

        while (work)
        {
            PVFDYNF_SYM_REQUEST sym;

            sym = CONTAINING_RECORD(work, VFDYNF_SYM_REQUEST, Entry);

            work = work->Next;

            switch (sym->Type)
            {
                case SymSymbols:
                {
                    sym->Status = AVrfpSymResolveSymbols(&sym->Symbols);
                    break;
                }
                case SymDllLoad:
                {
                    sym->Status = AVrfpSymDllLoad(&sym->DllLoad);
                    break;
                }
                case SymDllUnload:
                {
                    sym->Status = AVrfpSymDllUnload(&sym->DllUnload);
                    break;
                }
                DEFAULT_UNREACHABLE;
            }

            NtSetEvent(sym->Event, NULL);

            AVrfpSymDereference(sym);
        }

        NtResetEvent(AVrfpSymContext.WorkQueueEvent, NULL);
    }

    return STATUS_SUCCESS;
}

VOID AVrfpSymEnqueue(
    _In_ VFDYNF_SYM_REQUEST_TYPE Type,
    _In_ PVFDYNF_SYM_REQUEST Sym
    )
{
    Sym->Status = STATUS_PENDING;
    Sym->Type = Type;

    NtResetEvent(Sym->Event, NULL);

    AVrfpSymReference(Sym);

    if (!RtlInterlockedPushEntrySList(&AVrfpSymContext.WorkQueue, &Sym->Entry))
    {
        NtSetEvent(AVrfpSymContext.WorkQueueEvent, NULL);
    }
}

BOOLEAN AvrfIsSymProviderThread(
    VOID
    )
{
    HANDLE threadId;

    threadId = NtCurrentThreadId();

    if ((threadId == AVrfpSymContext.WorkerThreadId) ||
        (threadId == ReadPointerAcquire(&AVrfpSymContext.InitThreadId)))
    {
        return TRUE;
    }

    return FALSE;
}

NTSTATUS AVrfSymGetSymbols(
    _In_count_(FramesCount) CONST PVOID* Frames,
    _In_ ULONG FramesCount,
    _Out_ PUNICODE_STRING* StackSymbols,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    NTSTATUS status;
    ULONG abandoned;
    PVFDYNF_SYM_REQUEST sym;

    *StackSymbols = NULL;

    abandoned = (ULONG)ReadAcquire(&AVrfpSymContext.CurrentAbandoned);
    if (abandoned >= AVrfProperties.SymAbandonedThreshold)
    {
        //
        // The number of queued an abandoned requests has reached a limit which
        // justifies trying to allow the process to recover. Do not allow any
        // more symbol resolution requests until the system drops back below
        // the threshold. The worker thread is currently abandoning work in the
        // queue in order to recover.
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sym = AVrfpSymCreateRequest();
    if (!sym)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    FramesCount = min(FramesCount, ARRAYSIZE(sym->Symbols.Frames));

    RtlCopyMemory(sym->Symbols.Frames, Frames, FramesCount * sizeof(PVOID));
    sym->Symbols.FramesCount = FramesCount;

    AVrfpSymEnqueue(SymSymbols, sym);

    status = NtWaitForSingleObject(sym->Event, FALSE, Timeout);
    if (status != STATUS_SUCCESS)
    {
        AVrfpSymAbandonSymbolsRequest(sym);
        AVrfpSymDereference(sym);
        return status;
    }

    status = sym->Status;
    if (NT_SUCCESS(status))
    {
        *StackSymbols = &sym->Symbols.StackSymbols;
    }
    else
    {
        AVrfpSymDereference(sym);
    }

    return status;
}

VOID AVrfSymFreeSymbols(
    _In_ PUNICODE_STRING StackSymbols
    )
{
    PVFDYNF_SYM_REQUEST sym;

    sym = CONTAINING_RECORD(StackSymbols,
                            VFDYNF_SYM_REQUEST,
                            Symbols.StackSymbols);

    AVrfpSymDereference(sym);
}

VOID AVrfSymDllLoad(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize
    )
{
    PVFDYNF_SYM_REQUEST sym;

    sym = AVrfpSymCreateRequest();
    if (!sym)
    {
        return;
    }

    sym->DllLoad.DllBase = DllBase;
    sym->DllLoad.DllSize = DllSize;

    StringCchCopyW(sym->DllLoad.DllName,
                   ARRAYSIZE(sym->DllLoad.DllName),
                   DllName);

    AVrfpSymEnqueue(SymDllLoad, sym);

    AVrfpSymDereference(sym);
}

VOID AVrfSymDllUnload(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize
    )
{
    PVFDYNF_SYM_REQUEST sym;

    sym = AVrfpSymCreateRequest();
    if (!sym)
    {
        return;
    }

    sym->DllUnload.DllBase = DllBase;
    sym->DllLoad.DllSize = DllSize;

    StringCchCopyW(sym->DllLoad.DllName,
                   ARRAYSIZE(sym->DllLoad.DllName),
                   DllName);

    AVrfpSymEnqueue(SymDllUnload, sym);

    AVrfpSymDereference(sym);
}

BOOLEAN AVrfSymProcessAttach(
    VOID
    )
{
    NTSTATUS status;
    CLIENT_ID clientId;

    if (AVrfpSymContext.Initialized)
    {
        return TRUE;
    }

    AVrfInitializeCriticalSection(&AVrfpSymContext.CriticalSection);

    RtlInitializeSListHead(&AVrfpSymContext.WorkQueue);
    RtlInitializeSListHead(&AVrfpSymContext.FreeList);

    status = NtCreateEvent(&AVrfpSymContext.WorkQueueEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           NotificationEvent,
                           FALSE);
    if (!NT_SUCCESS(status))
    {
        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "failed to create symbol provider event (0x%08x)",
                     status);

        return FALSE;
    }

    status = RtlCreateUserThread(NtCurrentProcess(),
                                 NULL,
                                 FALSE,
                                 0,
                                 0,
                                 0,
                                 AVrfpSymWorker,
                                 NULL,
                                 &AVrfpSymContext.WorkerThreadHandle,
                                 &clientId);
    if (!NT_SUCCESS(status))
    {
        NtClose(AVrfpSymContext.WorkQueueEvent);
        AVrfpSymContext.WorkQueueEvent = NULL;

        AVrfDbgPrint(DPFLTR_ERROR_LEVEL,
                     "failed to create symbol provider thread (0x%08x)",
                     status);

        return FALSE;
    }

    AVrfpSymContext.WorkerThreadId = clientId.UniqueThread;

    AVrfpSymContext.Initialized = TRUE;

    return TRUE;
}

VOID AVrfSymProcessDetach(
    VOID
    )
{
    PSLIST_ENTRY entry;

    if (!AVrfpSymContext.Initialized)
    {
        return;
    }

    WriteReleaseBoolean(&AVrfpSymContext.StopWorker, TRUE);
    NtSetEvent(AVrfpSymContext.WorkQueueEvent, NULL);
    NtWaitForSingleObject(AVrfpSymContext.WorkerThreadHandle, FALSE, FALSE);
    NtClose(AVrfpSymContext.WorkerThreadHandle);
    NtClose(AVrfpSymContext.WorkQueueEvent);

    entry = RtlInterlockedFlushSList(&AVrfpSymContext.FreeList);
    while (entry)
    {
        PVFDYNF_SYM_REQUEST sym;

        sym = CONTAINING_RECORD(entry, VFDYNF_SYM_REQUEST, Entry);

        entry = entry->Next;

        AVrfpSymFreeRequest(sym);
    }

    if (ReadAcquireBoolean(&AVrfpSymContext.SymInitialized))
    {
        Delay_SymCleanup(NtCurrentProcess());
    }

    AVrfDeleteCriticalSection(&AVrfpSymContext.CriticalSection);

    AVrfpSymContext.Initialized = FALSE;
}
