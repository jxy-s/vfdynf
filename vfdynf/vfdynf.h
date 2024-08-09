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
#include <assert.h>

#include <pcre2_vfdynf.h>

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

#ifdef _DEBUG
#define AVRF_ASSERT(_exp) _Analysis_assume_(_exp); if (!(_exp)) __debugbreak()
#else
#define AVRF_ASSERT(_exp) ((void)0)
#endif

#define VFDYNF_FAULT_TYPE_WAIT            0x00000001ul
#define VFDYNF_FAULT_TYPE_HEAP            0x00000002ul
#define VFDYNF_FAULT_TYPE_VMEM            0x00000004ul
#define VFDYNF_FAULT_TYPE_REG             0x00000008ul
#define VFDYNF_FAULT_TYPE_FILE            0x00000010ul
#define VFDYNF_FAULT_TYPE_EVENT           0x00000020ul
#define VFDYNF_FAULT_TYPE_SECTION         0x00000040ul
#define VFDYNF_FAULT_TYPE_OLE             0x00000080ul
#define VFDYNF_FAULT_TYPE_INPAGE          0x00000100ul
#define VFDYNF_FAULT_TYPE_FUZZ_REG        0x00000200ul
#define VFDYNF_FAULT_TYPE_FUZZ_FILE       0x00000400ul
#define VFDYNF_FAULT_TYPE_FUZZ_MMAP       0x00000800ul

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

#define VFDYNF_FAULT_TYPE_COUNT           12ul

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
                                 VFDYNF_FAULT_TYPE_FUZZ_MMAP)

#define VFDYNF_FAULT_DEFAULT_MASK (VFDYNF_FAULT_VALID_MASK                & ~(\
                                   VFDYNF_FAULT_TYPE_FUZZ_REG                |\
                                   VFDYNF_FAULT_TYPE_FUZZ_FILE               |\
                                   VFDYNF_FAULT_TYPE_FUZZ_MMAP))

#define VFDYN_EXCLUSIONS_REGEX_MAX_LENGTH (16 * 1024)

typedef struct _VFDYNF_PROPERTIES
{
    ULONG GracePeriod;
    WCHAR SymbolSearchPath[1024];
    WCHAR ExclusionsRegex[VFDYN_EXCLUSIONS_REGEX_MAX_LENGTH];
    ULONG DynamicFaultPeroid;
    ULONG64 EnableFaultMask;
    ULONG FaultProbability;
    ULONG FaultSeed;
    ULONG FuzzCorruptionBlocks;
    ULONG FuzzChaosProbability;
    ULONG FuzzSizeTruncateProbability;
    WCHAR TypeExclusionsRegex[VFDYNF_FAULT_TYPE_COUNT][VFDYN_EXCLUSIONS_REGEX_MAX_LENGTH];
} VFDYNF_PROPERTIES, *PVFDYNF_PROPERTIES;

#define VFDYNF_CODE_DEPRECATED_FUNCTION    0xdf01

// dllmain.c

extern VFDYNF_PROPERTIES AVrfProperties;
extern AVRF_LAYER_DESCRIPTOR AVrfLayerDescriptor;

// hooks.c

extern RTL_VERIFIER_DLL_DESCRIPTOR AVrfDllDescriptors[];

BOOLEAN AVrfHookProcessAttach(
    VOID
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

BOOLEAN AVrfFuzzProcessAttach(
    VOID
    );

VOID AVrfFuzzProcessDetach(
    VOID
    );

BOOLEAN AVrfFuzzProbability(
    _In_ ULONG Probability
    );

VOID AVrfFuzzBuffer(
    _Inout_bytecount_(Length) PVOID Buffer,
    _In_ SIZE_T Length
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

// fault.c

BOOLEAN AVrfFaultProcessAttach(
    VOID
    );

VOID AVrfFaultProcessDetach(
    VOID
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
