/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

namespace fault 
{

struct StackEntry
{
    bool Excluded;
    uint64_t FaultMask;
};

DWORD g_TypeBase = MAXDWORD;
bool g_Initialized = false;
std::mutex g_Lock;
uint64_t g_LastClear = 0;
std::unordered_map<uint32_t, StackEntry> g_StackTable;
std::once_flag g_ExclusionsRegexOnce;
std::vector<std::wregex> g_ExclusionsRegex;

inline
static
DWORD
FaultTypeClass(
    Type FaultType
    )
{
    assert(g_TypeBase != MAXDWORD);
    return (g_TypeBase + static_cast<DWORD>(FaultType));
}

BOOL
CALLBACK 
SymbolRegsteredCallback(
    _In_ HANDLE hProcess,
    _In_ ULONG ActionCode,
    _In_opt_ ULONG64 CallbackData,
    _In_opt_ ULONG64 UserContext
    )
{
    UNREFERENCED_PARAMETER(hProcess);
    UNREFERENCED_PARAMETER(UserContext);

    switch (ActionCode)
    {
        case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE: 
        {
            auto info = reinterpret_cast<PIMAGEHLP_DEFERRED_SYMBOL_LOADW64>(CallbackData);
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_INFO_LEVEL,
                       "AVRF: loaded symbols %ls\n",
                       info->FileName);
            break;
        }
        case CBA_DEFERRED_SYMBOL_LOAD_FAILURE: 
        {
            auto info = reinterpret_cast<PIMAGEHLP_DEFERRED_SYMBOL_LOADW64>(CallbackData);
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: failed to loaded symbols %ls\n",
                       info->FileName);
            break;
        }
        case CBA_DEFERRED_SYMBOL_LOAD_PARTIAL: 
        {
            auto info = reinterpret_cast<PIMAGEHLP_DEFERRED_SYMBOL_LOADW64>(CallbackData);
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: partially loaded symbols %ls\n",
                       info->FileName);
            break;
        }
        case CBA_SYMBOLS_UNLOADED: 
        {
            auto info = reinterpret_cast<PIMAGEHLP_DEFERRED_SYMBOL_LOADW64>(CallbackData);
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

static
void
InitExclusionsRegex(
    void
    )
{
    //
    // The exclusions regular expressions is a REG_MULTI_SZ from the properties
    // verifier loads on our behalf. Parse each block of the multi terminated
    // string into the regex vector. We do this so we don't have to construct
    // the regex object every time. This is called once during the first
    // evaluation.
    //

    size_t offset = 0;
    for (;;)
    {
        UNICODE_STRING expr;
        RtlInitUnicodeString(&expr, &g_Properties.ExclusionsRegex[offset]);
        if (expr.Length == 0)
        {
            break;
        }

        try
        {
            g_ExclusionsRegex.emplace_back(expr.Buffer, 
                                           expr.Length / sizeof(WCHAR),
                                           std::wregex::ECMAScript | 
                                               std::wregex::optimize);
        }
        catch (const std::exception& exc)
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: exception (%s) raised processing regex!\n",
                       exc.what());
            __debugbreak();
        }

        offset += ((expr.Length / sizeof(WCHAR)) + 1);
    }
}

static
bool
IsStackOverriddenByRegex(
    _In_ const std::wstring& StackSymbols 
    )
{
    std::call_once(g_ExclusionsRegexOnce, InitExclusionsRegex);

    for (const auto& entry : g_ExclusionsRegex)
    {
        try
        {
            if (std::regex_search(StackSymbols, entry))
            {
                return true;
            }
        }
        catch (const std::exception& exc)
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "AVRF: exception (%s) raised processing regex!\n",
                       exc.what());
            __debugbreak();
        }
    }

    return false;
}

} // namespace fault

bool
fault::ShouldFaultInject(
    _In_ Type FaultType,
    _In_ _Maybenull_ void* CallerAddress
    ) noexcept try
{
    if (!g_Initialized)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: fault injection not yet initialized\n");
        return false;
    }

    if (CallerAddress == nullptr)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_WARNING_LEVEL,
                   "AVRF: caller address is null\n");
        return false;
    }

    if ((g_Properties.EnableFaultMask & fault::FaultTypeToBit(FaultType)) == 0)
    {
        //
        // Fault type is not enabled.
        //
        return false;
    }

    if (VerifierShouldFaultInject(FaultTypeClass(FaultType), 
                                  CallerAddress) == FALSE)
    {
        return false;
    }

    DWORD hash;
    void* frames[250];
    WORD count = RtlCaptureStackBackTrace(2, ARRAYSIZE(frames), frames, &hash);

    std::unique_lock lock(g_Lock);

    if (g_Properties.DynamicFaultPeroid > 0)
    {
        if (g_LastClear == 0)
        {
            g_LastClear = NtGetTickCount64();
        }
        else if ((g_LastClear + g_Properties.DynamicFaultPeroid) <= NtGetTickCount64())
        {
            g_LastClear = NtGetTickCount64();
            g_StackTable.clear();
        }
    }

    auto [it, inserted] = g_StackTable.try_emplace(hash);
    if (!inserted)
    {
        //
        // We already evaluated this stack.
        // 1. it's excluded
        // 2. we should inject a fault of an unseen type
        // 3. we already injected a fault and shouldn't
        //

        if (it->second.Excluded)
        {
            return false;
        }

        if ((it->second.FaultMask & FaultTypeToBit(FaultType)) == 0)
        {
            it->second.FaultMask |= FaultTypeToBit(FaultType);
            return true;
        }

        return false;
    }

    if (g_Properties.ExclusionsRegex[0] == '\0')
    {
        //
        // There are no exclusion expressions, skip the work below.
        //
        it->second.FaultMask = FaultTypeToBit(FaultType);
        return true;
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
    std::wstring stackSymbols;

    for (WORD i = 0; i < count; i++)
    {
        char buffer[sizeof(SYMBOL_INFOW) + ((MAX_SYM_NAME + 1) * sizeof(WCHAR))];
        auto info = reinterpret_cast<PSYMBOL_INFOW>(buffer);

        memset(info, 0, sizeof(*info));
        info->SizeOfStruct = sizeof(SYMBOL_INFOW);
        info->MaxNameLen = MAX_SYM_NAME;

        DWORD64 disp;
        if (SymFromAddrW(NtCurrentProcess(), 
                         reinterpret_cast<DWORD64>(frames[i]), 
                         &disp, 
                         info) == FALSE)
        {
            //
            // Refresh the module list and try again.
            //
            SymRefreshModuleList(NtCurrentProcess());

            if (SymFromAddrW(NtCurrentProcess(), 
                             reinterpret_cast<DWORD64>(frames[i]), 
                             &disp, 
                             info) == FALSE)
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
                memset(info, 0, sizeof(*info));
            }
        }

        //
        // To minimize the tracking we have to do and since we're already
        // injected into the process, we're going to just use the loader
        // module list to identify the module of the symbol. First, try
        // to get the loader lock - if we can't we just concede and get out
        // of the way of the system - we won't inject a fault.
        //
        PVOID ldrCookie;
        ULONG ldrDisp;
        auto status = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
                                        &ldrDisp,
                                        &ldrCookie);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: failed to acquire loader lock (0x%08x)!\n",
                       status);
            g_StackTable.erase(it);
            return false;
        }
        if (ldrDisp != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_WARNING_LEVEL,
                       "AVRF: loader lock is busy!\n");
            g_StackTable.erase(it);
            return false;
        }

        PLDR_DATA_TABLE_ENTRY data = nullptr;
        auto modList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
        for (auto entry = modList->Flink; entry != modList; entry = entry->Flink)
        {
            auto item = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (info->ModBase != 0)
            {
                auto base = reinterpret_cast<PVOID>(info->ModBase);
                if (item->DllBase == base)
                {
                    data = item;
                    break;
                }
            }
            else
            {
                //
                // Either dbghelp didn't give us a module base or the call to
                // resolve the symbol name failed. Identify the module by the
                // extents.
                //
                auto end = Add2Ptr(item->DllBase, item->SizeOfImage);
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

        wchar_t symBuff[MAX_SYM_NAME + 1 + MAX_PATH];
        UNICODE_STRING symbol;
        symbol.Buffer = symBuff;
        symbol.Length = 0;
        symbol.MaximumLength = sizeof(symBuff);

        if (data == nullptr)
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

        stackSymbols.append(symbol.Buffer, symbol.Length / sizeof(WCHAR));
        stackSymbols.push_back(L'\n');
    }

    if (!stackSymbols.empty())
    {
        //
        // Pop the last new line.
        //
        stackSymbols.pop_back();

        if (IsStackOverriddenByRegex(stackSymbols))
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID,
                       DPFLTR_INFO_LEVEL,
                       "AVRF: stack excluded by regular expression\n");

            //
            // Cache the decision for this stack hash.
            //
            it->second.Excluded = true;
            return false;
        }
    }

    it->second.FaultMask = FaultTypeToBit(FaultType);
    return true;
}
catch (const std::exception& exc)
{
    DbgPrintEx(DPFLTR_VERIFIER_ID,
               DPFLTR_ERROR_LEVEL,
               "AVRF: exception (%s) raised during fault injection!\n",
               exc.what());
    __debugbreak();
    return false;
}

bool
fault::ProcessAttach(
    void
    )
{
    std::unique_lock lock(g_Lock);

    if (g_Properties.SymbolSearchPath[0] == L'\0')
    {
        if (SymInitializeW(NtCurrentProcess(), nullptr, FALSE) == FALSE)
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID, 
                       DPFLTR_ERROR_LEVEL, 
                       "AVRF: failed to initialize symbols (%lu)\n",
                       NtCurrentTeb()->LastErrorValue);
            return false;
        }
    }
    else
    {
        if (SymInitializeW(NtCurrentProcess(), 
                           g_Properties.SymbolSearchPath, 
                           FALSE) == FALSE)
        {
            DbgPrintEx(DPFLTR_VERIFIER_ID, 
                       DPFLTR_ERROR_LEVEL, 
                       "AVRF: failed to initialize symbols (%lu)\n",
                       NtCurrentTeb()->LastErrorValue);
            return false;
        }
    }

    SymSetOptions(SymGetOptions() | SYMOPT_UNDNAME);
    SymRegisterCallbackW64(NtCurrentProcess(), SymbolRegsteredCallback, 0);
    SymRefreshModuleList(NtCurrentProcess());

    auto err = VerifierRegisterFaultInjectProvider(static_cast<DWORD>(Type::Max),
                                                   &g_TypeBase);
    if (err != ERROR_SUCCESS)
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID, 
                   DPFLTR_ERROR_LEVEL, 
                   "AVRF: failed to register fault injection provider (%lu)\n",
                   err);
        return false;
    }

    if (g_Properties.GracePeriod)
    {
        VerifierSuspendFaultInjection(g_Properties.GracePeriod);
    }

    //
    // We ask for everything and handle excluding ranges ourself.
    //
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::Wait), 
                                            nullptr, 
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::Heap),
                                            nullptr, 
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::VMem),
                                            nullptr, 
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::Reg), 
                                            nullptr,
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::File),
                                            nullptr, 
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::Event), 
                                            nullptr,
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::Section),
                                            nullptr, 
                                            Add2Ptr(nullptr, MAXULONG_PTR));
    VerifierEnableFaultInjectionTargetRange(FaultTypeClass(Type::Ole), 
                                            nullptr, 
                                            Add2Ptr(nullptr, MAXULONG_PTR));

    //
    // By default the system doesn't rely on probability for fault injection.
    // However, there are properties to set the probability and seed if desired.
    //

    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Wait), 
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Heap),
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::VMem),
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Reg),
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::File),
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Event),
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Section),
                                         g_Properties.FaultProbability);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Ole),
                                         g_Properties.FaultProbability);

    VerifierSetAPIClassName(FaultTypeClass(Type::Wait), L"Wait APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Heap), L"Heap APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::VMem), L"Virtual Memory APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Reg), L"Registry APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::File), L"File APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Event), L"Event APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Section), L"Section APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Ole), L"OLE String APIs");

    if (g_Properties.FaultSeed == 0)
    {
        auto seed = HandleToULong(NtCurrentThreadId()) ^ NtGetTickCount();
        auto rand = RtlRandomEx(&seed);
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_INFO_LEVEL,
                   "AVRF: generated and using random fault injection seed %lu\n",
                   rand);
        VerifierSetFaultInjectionSeed(rand);
    }
    else
    {
        VerifierSetFaultInjectionSeed(g_Properties.FaultSeed);
    }

    DbgPrintEx(DPFLTR_VERIFIER_ID,
               DPFLTR_INFO_LEVEL,
               "AVRF: dynamic fault injection initialized\n");

    g_Initialized = true;
    return true;
}

void
fault::ProcessDetach(
    void
    )
{
    std::unique_lock lock(g_Lock);

    SymCleanup(NtCurrentProcess());

    g_StackTable.clear();

    g_Initialized = false;
}
