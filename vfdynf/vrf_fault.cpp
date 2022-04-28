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

inline
static
uint64_t
FaultTypeToBit(
    Type FaultType
    )
{
    return (1ull << (uint32_t)FaultType);
}

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

static
bool
IsFrameOverriddenByRegex(
    _In_ PUNICODE_STRING Symbol
    )
{
    size_t offset = 0;
    for (;;)
    {
        UNICODE_STRING wild;
        RtlInitUnicodeString(&wild, &g_Properties.ExclusionsRegex[offset]);
        if (wild.Length == 0)
        {
            break;
        }

        try
        {
            std::wregex regex(wild.Buffer, wild.Length / sizeof(WCHAR));
            std::wstring_view symbol(Symbol->Buffer, Symbol->Length / sizeof(WCHAR));
            if (std::regex_match(symbol.begin(), symbol.end(), regex))
            {
                return true;
            }
        }
        catch (const std::exception& exc)
        {
            DbgPrint("JXY: exception (%s) raised processing regex!",
                     exc.what());
            __debugbreak();
        }

        offset += ((wild.Length / sizeof(WCHAR)) + 1);
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
        DbgPrint("JXY: fault injection not yet initialized\n");
        return false;
    }

    if (CallerAddress == nullptr)
    {
        DbgPrint("JXY: caller address is null\n");
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
        if (it->second.Excluded)
        {
            return false;
        }

        if ((it->second.FaultMask & FaultTypeToBit(FaultType)) == 0)
        {
            it->second.FaultMask |= FaultTypeToBit(FaultType);
            return true;
        }

        //
        // We already injected a fault for this stash hash, skip it.
        //
        return false;
    }

    //
    // Classify the stack. Check for overrides by symbols/etc.
    //
    bool overridden = false;

    for (WORD i = 0; i < count; i++)
    {
        char buffer[sizeof(SYMBOL_INFOW) + ((MAX_SYM_NAME + 1) * sizeof(WCHAR))];
        auto info = reinterpret_cast<PSYMBOL_INFOW>(buffer);
        info->SizeOfStruct = sizeof(SYMBOL_INFOW);
        info->MaxNameLen = MAX_SYM_NAME;

        DWORD64 disp;
        if (SymFromAddrW(NtCurrentProcess(), (DWORD64)frames[i], &disp, info) == FALSE)
        {
            DbgPrint("JXY: failed to get symbol info\n");
            continue;
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
        if (!NT_SUCCESS(LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
                                          &ldrDisp,
                                          &ldrCookie)))
        {
            DbgPrint("JXY: failed to acquire loader lock!");
            g_StackTable.erase(it);
            return false;
        }
        if (ldrDisp != LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
        {
            DbgPrint("JXY: loader lock is busy!");
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

        RtlAppendUnicodeToString(&symbol, L"!");
        RtlAppendUnicodeToString(&symbol, info->Name);

        //
        // We're done with the loader lock.
        //
        LdrUnlockLoaderLock(0, ldrCookie);

        DbgPrint("JXY: %wZ\n", &symbol);

        if (IsFrameOverriddenByRegex(&symbol))
        {
            overridden = true;
            break;
        }
    }

    it->second.Excluded = overridden;
    if (it->second.Excluded)
    {
        return false;
    }

    it->second.FaultMask = FaultTypeToBit(FaultType);
    return true;
}
catch (const std::exception& exc)
{
    DbgPrint("JXY: exception (%s) raised during fault injection!",
             exc.what());
    __debugbreak();
    return false;
}

bool
fault::ProcessAttach(
    void
    )
{
    if (g_Properties.SymbolSearchPath[0] == L'\0')
    {
        if (SymInitializeW(NtCurrentProcess(), nullptr, TRUE) == FALSE)
        {
            return false;
        }
    }
    else
    {
        if (SymInitializeW(NtCurrentProcess(), 
                           g_Properties.SymbolSearchPath, 
                           TRUE) == FALSE)
        {
            return false;
        }
    }

    if (VerifierRegisterFaultInjectProvider(static_cast<DWORD>(Type::Max),
                                            &g_TypeBase) != ERROR_SUCCESS)
    {
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
    // Set maximum probability so VerifierShouldInjectFault always triggers.
    // The dynamic stack-based fault injection will get better coverage than
    // randomly injecting faults.
    //
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Wait), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Heap), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::VMem), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Reg), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::File), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Event), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Section), MAXDWORD);
    VerifierSetFaultInjectionProbability(FaultTypeClass(Type::Ole), MAXDWORD);

    VerifierSetAPIClassName(FaultTypeClass(Type::Wait), L"Wait APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Heap), L"Heap APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::VMem), L"Virtual Memory APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Reg), L"Registry APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::File), L"File APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Event), L"Event APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Section), L"Section APIs");
    VerifierSetAPIClassName(FaultTypeClass(Type::Ole), L"OLE String APIs");

    //
    // Again we don't rely on randomness, set the seed to 0.
    //
    VerifierSetFaultInjectionSeed(0);

    g_Initialized = true;
    return true;
}

void
fault::ProcessDetach(
    void
    )
{
    g_StackTable.clear();
    g_Initialized = false;
}
