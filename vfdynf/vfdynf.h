/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#pragma once

#pragma warning(push)
#pragma warning(disable : 4115)
#define PHNT_NO_INLINE_INIT_STRING
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)

#include <intrin.h>
#include <vrfapi.h>
#include <bcrypt.h>
#include <DbgHelp.h>
#include <oleauto.h>
#include <WinSock2.h>
#include <assert.h>

#include <pcre2_vfdynf.h>
#include <vfdynfapi.h>

#include <resource.h>

#ifndef Add2Ptr
#define Add2Ptr(P, I) ((PVOID)((PUCHAR)(P) + (I)))
#endif
#ifndef PtrOffset
#define PtrOffset(B, O) ((ULONG)((ULONG_PTR)(O) - (ULONG_PTR)(B)))
#endif
#ifndef FlagOn
#define FlagOn(_F, _SF) ((_F) & (_SF))
#endif
#ifndef BooleanFlagOn
#define BooleanFlagOn(F, SF) ((BOOLEAN)(((F) & (SF)) != 0))
#endif
#ifndef SetFlag
#define SetFlag(_F, _SF) ((_F) |= (_SF))
#endif
#ifndef ClearFlag
#define ClearFlag(_F, _SF) ((_F) &= ~(_SF))
#endif
#ifndef DPFLTR_MASK
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3
#define DPFLTR_MASK 0x80000000
#define DPFLTR_VERIFIER_ID 93
#endif DPFLTR_MASK

#define AVrfDbgPrint(level, format, ...)                                      \
DbgPrintEx(DPFLTR_VERIFIER_ID,                                                \
           level,                                                             \
           "AVRF [%04x:%04x]: " format "\n",                                  \
           (USHORT)(ULONG_PTR)NtCurrentProcessId(),                           \
           (USHORT)(ULONG_PTR)NtCurrentThreadId(),                            \
           __VA_ARGS__)

#define AVrfDbgPuts(level, string)                                            \
DbgPrintEx(DPFLTR_VERIFIER_ID,                                                \
           level,                                                             \
           "AVRF [%04x:%04x]: " string "\n",                                  \
           (USHORT)(ULONG_PTR)NtCurrentProcessId(),                           \
           (USHORT)(ULONG_PTR)NtCurrentThreadId())

#ifdef _DEBUG
#define AVRF_ASSERT(_exp) _Analysis_assume_(_exp); if (!(_exp)) __debugbreak()
#else
#define AVRF_ASSERT(_exp) ((void)0)
#endif

FORCEINLINE
VOID
AVrfInitializeCriticalSection(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection
    )
{
    NTSTATUS status;

    status = RtlInitializeCriticalSection(CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));
}

FORCEINLINE
VOID
AVrfDeleteCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    )
{
    NTSTATUS status;

    status = RtlDeleteCriticalSection(CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));
}

_Acquires_exclusive_lock_(*CriticalSection)
FORCEINLINE
VOID
AVrfEnterCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    )
{
    NTSTATUS status;

    status = RtlEnterCriticalSection(CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));
}

_Releases_exclusive_lock_(*CriticalSection)
FORCEINLINE
VOID
AVrfLeaveCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    )
{
    NTSTATUS status;

    status = RtlLeaveCriticalSection(CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));
}

FORCEINLINE
VOID
WriteReleaseBoolean(
    _Out_ _Interlocked_operand_ BOOLEAN volatile* Destination,
    _In_ BOOLEAN Value
    )
{
    WriteRelease8((CHAR volatile*)Destination, (CHAR)Value);
}

FORCEINLINE
BOOLEAN
ReadAcquireBoolean(
    _In_ _Interlocked_operand_ BOOLEAN const volatile* Source
    )
{
    return (BOOLEAN)ReadAcquire8((CHAR const volatile*)Source);
}

FORCEINLINE
BOOLEAN
InterlockedExchangeAcquireBoolean(
    _Inout_ _Interlocked_operand_ BOOLEAN volatile* Target,
    _In_ BOOLEAN Value
    )
{
    return (BOOLEAN)InterlockedExchangeAcquire8((CHAR volatile*)Target,
                                                (CHAR)Value);
}

//
// See vfdynfapi.h for VFDYNF_FAULT_TYPE_*
//

#define VFDYNF_FAULT_TYPE_INDEX_WAIT      0ul
#define VFDYNF_FAULT_TYPE_INDEX_HEAP      1ul
#define VFDYNF_FAULT_TYPE_INDEX_VMEM      2ul
#define VFDYNF_FAULT_TYPE_INDEX_REG       3ul
#define VFDYNF_FAULT_TYPE_INDEX_FILE      4ul
#define VFDYNF_FAULT_TYPE_INDEX_EVENT     5ul
#define VFDYNF_FAULT_TYPE_INDEX_SECTION   6ul
#define VFDYNF_FAULT_TYPE_INDEX_OLE       7ul
#define VFDYNF_FAULT_TYPE_INDEX_INPAGE    8ul
#define VFDYNF_FAULT_TYPE_INDEX_FUZZ_REG  9ul
#define VFDYNF_FAULT_TYPE_INDEX_FUZZ_FILE 10ul
#define VFDYNF_FAULT_TYPE_INDEX_FUZZ_MMAP 11ul
#define VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET  12ul

#define VFDYNF_FAULT_TYPE_COUNT           13ul

#define VFDYNF_FAULT_VALID_MASK (VFDYNF_FAULT_TYPE_WAIT                      |\
                                 VFDYNF_FAULT_TYPE_HEAP                      |\
                                 VFDYNF_FAULT_TYPE_VMEM                      |\
                                 VFDYNF_FAULT_TYPE_REG                       |\
                                 VFDYNF_FAULT_TYPE_FILE                      |\
                                 VFDYNF_FAULT_TYPE_EVENT                     |\
                                 VFDYNF_FAULT_TYPE_SECTION                   |\
                                 VFDYNF_FAULT_TYPE_OLE                       |\
                                 VFDYNF_FAULT_TYPE_INPAGE                    |\
                                 VFDYNF_FAULT_TYPE_FUZZ_REG                  |\
                                 VFDYNF_FAULT_TYPE_FUZZ_FILE                 |\
                                 VFDYNF_FAULT_TYPE_FUZZ_MMAP                 |\
                                 VFDYNF_FAULT_TYPE_FUZZ_NET)

#define VFDYNF_FAULT_DEFAULT_MASK (VFDYNF_FAULT_VALID_MASK                & ~(\
                                   VFDYNF_FAULT_TYPE_FUZZ_REG                |\
                                   VFDYNF_FAULT_TYPE_FUZZ_FILE               |\
                                   VFDYNF_FAULT_TYPE_FUZZ_MMAP               |\
                                   VFDYNF_FAULT_TYPE_FUZZ_NET))

#define VFDYN_SYMSEARCH_MAX_LENGTH (1024)
#define VFDYN_REGEX_MAX_LENGTH     (16 * 1024)

typedef struct _VFDYNF_PROPERTIES
{
    ULONG GracePeriod;
    WCHAR SymbolSearchPath[VFDYN_SYMSEARCH_MAX_LENGTH];
    WCHAR IncludeRegex[VFDYN_REGEX_MAX_LENGTH];
    WCHAR ExclusionsRegex[VFDYN_REGEX_MAX_LENGTH];
    ULONG DynamicFaultPeroid;
    ULONG64 EnableFaultMask;
    ULONG FaultProbability;
    ULONG FaultSeed;
    ULONG FuzzSeed;
    ULONG FuzzCorruptionBlocks;
    ULONG FuzzChaosProbability;
    ULONG FuzzSizeTruncateProbability;
    ULONG64 HeapReasonableAllocLimit;
    BOOLEAN EnableFaultsInLdrPath;
    BOOLEAN EnableWriteFuzzedDataChecks;
    ULONG SymResolvePriority;
    ULONG SymResolveTimeout;
    ULONG SymAbandonedThreshold;
    WCHAR StopRegex[VFDYN_REGEX_MAX_LENGTH];
    WCHAR TypeIncludeRegex[VFDYNF_FAULT_TYPE_COUNT][VFDYN_REGEX_MAX_LENGTH];
    WCHAR TypeExclusionsRegex[VFDYNF_FAULT_TYPE_COUNT][VFDYN_REGEX_MAX_LENGTH];
} VFDYNF_PROPERTIES, *PVFDYNF_PROPERTIES;

#define VFDYNF_CODE_DEPRECATED_FUNCTION    0xdf01
#define VFDYNF_CODE_HEAP_ALLOC_LIMIT       0xdf02
#define VFDYNF_CODE_WRITE_FUZZED_DATA_REG  0xdf03
#define VFDYNF_CODE_WRITE_FUZZED_DATA_FILE 0xdf04 // not yet implemented
#define VFDYNF_CODE_WRITE_FUZZED_DATA_NET  0xdf05 // not yet implemented

// dllmain.c

extern VFDYNF_PROPERTIES AVrfProperties;
extern AVRF_LAYER_DESCRIPTOR AVrfLayerDescriptor;

typedef
_Function_class_(AVRF_RUN_ONCE_ROUTINE)
BOOLEAN
NTAPI
AVRF_RUN_ONCE_ROUTINE(
    VOID
    );
typedef AVRF_RUN_ONCE_ROUTINE* PAVRF_RUN_ONCE_ROUTINE;

typedef volatile LONG AVRF_RUN_ONCE;
typedef AVRF_RUN_ONCE* PAVRF_RUN_ONCE;
#define AVRF_RUN_ONCE_INIT 0

BOOLEAN AVrfRunOnce(
    _Inout_ PAVRF_RUN_ONCE Once,
    _In_ PAVRF_RUN_ONCE_ROUTINE Routine,
    _In_ BOOLEAN Async
    );

typedef struct _AVRF_MODULE_ENTRY
{
    LIST_ENTRY Entry;
    PVOID BaseAddress;
    PVOID EndAddress;
    UNICODE_STRING BaseName;
    UNICODE_STRING FullName;
    BYTE Buffer[ANYSIZE_ARRAY];
} AVRF_MODULE_ENTRY, *PAVRF_MODULE_ENTRY;

typedef
_Function_class_(AVRF_MODULE_ENUM_CALLBACK)
BOOLEAN
NTAPI
AVRF_MODULE_ENUM_CALLBACK(
    _In_ PAVRF_MODULE_ENTRY Module,
    _In_opt_ PVOID Context
    );
typedef AVRF_MODULE_ENUM_CALLBACK* PAVRF_MODULE_ENUM_CALLBACK;

BOOLEAN AVrfEnumLoadedModules(
    _In_ PAVRF_MODULE_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

typedef struct _VFDYNF_TLS
{
    ULONG SuppressFaultMask;
} VFDYNF_TLS, *PVFDYNF_TLS;

_Maybenull_
PVFDYNF_TLS AVrfGetTls(
    VOID
    );

// stop.c

BOOLEAN AVrfShouldVerifierStop(
    _In_opt_ _Maybenull_ PVOID CallerAddress
    );

BOOLEAN AVrfStopProcessAttach(
    VOID
    );

VOID AVrfStopProcessDetach(
    VOID
    );

// hooks.c

extern RTL_VERIFIER_DLL_DESCRIPTOR AVrfDllDescriptors[];

BOOLEAN AVrfLinkHooks(
    VOID
    );

// symprv.c

BOOLEAN AVrfSymProcessAttach(
    VOID
    );

VOID AVrfSymProcessDetach(
    VOID
    );

VOID AVrfSymDllLoad(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize
    );

VOID AVrfSymDllUnload(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize
    );

BOOLEAN AvrfIsSymProviderThread(
    VOID
    );

NTSTATUS AVrfSymGetSymbols(
    _In_count_(FramesCount) CONST PVOID* Frames,
    _In_ ULONG FramesCount,
    _Out_ PUNICODE_STRING* StackSymbols,
    _In_opt_ PLARGE_INTEGER Timeout
    );

VOID AVrfSymFreeSymbols(
    _In_ PUNICODE_STRING StackSymbols
    );

// except.c

VOID AVrfGuardToConvertToInPageError(
    _In_ PVOID Address
    );

VOID AVrfForgetGuardForInPageError(
    _In_ PVOID Address
    );

BOOLEAN AVrfExceptProcessAttach(
    VOID
    );

VOID AVrfExceptProcessDetach(
    VOID
    );

// fuzz.c

#define VFDYNF_FUZZ_SENTINEL '#'

FORCEINLINE
VOID AVrfFuzzFillMemory(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length
    )
{
    RtlFillMemory(Destination, Length, VFDYNF_FUZZ_SENTINEL);
}

BOOLEAN AVrfFuzzProcessAttach(
    VOID
    );

VOID AVrfFuzzProcessDetach(
    VOID
    );

ULONG AVrfFuzzRandom(
    VOID
    );

BOOLEAN AVrfFuzzProbability(
    _In_ ULONG Probability
    );

VOID AVrfFuzzBuffer(
    _Inout_bytecount_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG TypeIndex
    );

VOID AVrfFuzzSize(
    _Out_ PLARGE_INTEGER Size
    );

VOID AVrfFuzzSizeTruncate(
    _Inout_ PLARGE_INTEGER Size
    );

VOID AVrfFuzzSizeTruncateULong(
    _Inout_ PULONG Size
    );

VOID AVrfFuzzSizeTruncateWideString(
    _Inout_ PULONG Size
    );

PVOID AVrfFuzzMemoryMapping(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize
    );

PVOID AVrfForgetFuzzedMemoryMapping(
    _In_ PVOID BaseAddress
    );

BOOLEAN AVrfBufferIsPossiblyFuzzed(
    _In_reads_bytes_opt_(Length) CONST VOID* Buffer,
    _In_ SIZE_T Length
    );

// fault.c

BOOLEAN AVrfFaultProcessAttach(
    VOID
    );

VOID AVrfFaultProcessDetach(
    VOID
    );

BOOLEAN AVrfIsCallerIncluded(
    _In_ ULONG FaultType,
    _In_opt_ _Maybenull_ PVOID CallerAddress
    );

BOOLEAN AVrfShouldFaultInject(
    _In_ ULONG FaultType,
    _In_opt_ _Maybenull_ PVOID CallerAddress
    );

// stacktrk.c

typedef struct _AVRF_STACK_ENTRY
{
    ULONG Hash;
    BOOLEAN Excluded;
    ULONG64 FaultMask;
} AVRF_STACK_ENTRY, *PAVRF_STACK_ENTRY;
C_ASSERT(sizeof(AVRF_STACK_ENTRY) == 16);

typedef struct _AVRF_STACK_TABLE_BUCKET
{
    ULONG Capacity;
    ULONG Count;
    PAVRF_STACK_ENTRY Entries;
} AVRF_STACK_TABLE_BUCKET, *PAVRF_STACK_TABLE_BUCKET;

#define STACK_BUCKET_COUNT 17 // prime distribution for low nibble

typedef struct _AVRF_STACK_TABLE
{
    AVRF_STACK_TABLE_BUCKET Buckets[STACK_BUCKET_COUNT];
} AVRF_STACK_TABLE, *PAVRF_STACK_TABLE;

_Must_inspect_result_
_Success_(return != NULL)
PAVRF_STACK_ENTRY AVrfLookupStackEntry(
    _Inout_ PAVRF_STACK_TABLE Table,
    _In_ ULONG Hash
    );

_Must_inspect_impl_
_Success_(return != NULL)
PAVRF_STACK_ENTRY AVrfInsertStackEntry(
    _Inout_ PAVRF_STACK_TABLE Table,
    _In_opt_ PAVRF_STACK_ENTRY Before,
    _In_ ULONG Hash
    );

VOID AVrfRemoveStackEntry(
    _Inout_ PAVRF_STACK_TABLE Table,
    _In_ PAVRF_STACK_ENTRY Entry
    );

VOID AVrfClearStackTable(
    _Inout_ PAVRF_STACK_TABLE Table
    );

VOID AVrfInitializeStackTable(
    _Out_ PAVRF_STACK_TABLE Table
    );

VOID AVrfFreeStackTable(
    _Inout_ PAVRF_STACK_TABLE Table
    );
