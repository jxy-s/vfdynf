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
#include <DbgHelp.h>
#include <oleauto.h>
#include <assert.h>

#include <pcre2_vfdynf.h>

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
#define AVFR_ASSERT(_exp) _Analysis_assume_(_exp); if (!(_exp)) __debugbreak()
#else
#define AVFR_ASSERT(_exp) ((void)0)
#endif

typedef struct _VFDYNF_PROPERTIES
{
    ULONG GracePeriod;
    WCHAR SymbolSearchPath[1024];
    WCHAR ExclusionsRegex[64 * 1024];
    ULONG DynamicFaultPeroid;
    ULONG64 EnableFaultMask;
    ULONG FaultProbability;
    ULONG FaultSeed;
} VFDYNF_PROPERTIES, *PVFDYNF_PROPERTIES;

#define VFDYNF_FAULT_TYPE_WAIT     0x00000001ul
#define VFDYNF_FAULT_TYPE_HEAP     0x00000002ul
#define VFDYNF_FAULT_TYPE_VMEM     0x00000004ul
#define VFDYNF_FAULT_TYPE_REG      0x00000008ul
#define VFDYNF_FAULT_TYPE_FILE     0x00000010ul
#define VFDYNF_FAULT_TYPE_EVENT    0x00000020ul
#define VFDYNF_FAULT_TYPE_SECTION  0x00000040ul
#define VFDYNF_FAULT_TYPE_OLE      0x00000080ul

#define VFDYNF_FAULT_TYPE_COUNT    8ul

#define VFDYNF_FAULT_VALID_MASK (VFDYNF_FAULT_TYPE_WAIT                      |\
                                 VFDYNF_FAULT_TYPE_HEAP                      |\
                                 VFDYNF_FAULT_TYPE_VMEM                      |\
                                 VFDYNF_FAULT_TYPE_REG                       |\
                                 VFDYNF_FAULT_TYPE_FILE                      |\
                                 VFDYNF_FAULT_TYPE_EVENT                     |\
                                 VFDYNF_FAULT_TYPE_SECTION                   |\
                                 VFDYNF_FAULT_TYPE_OLE)

// dllmain.c

extern VFDYNF_PROPERTIES AVrfProperties;

VOID AVrfLayerSetRecursionCount(
    _In_ ULONG Value
    );

ULONG AVrfLayerGetRecursionCount(
    VOID
    );

// hooks.c

extern RTL_VERIFIER_DLL_DESCRIPTOR AVrfDllDescriptors[];

BOOLEAN AVrfHookProcessAttach(
    VOID
    );

// fault.c

BOOLEAN AVrfFaultProcessAttach(
    VOID
    );

VOID AVrfFaultProcessDetach(
    VOID
    );

BOOLEAN AvrfShouldFaultInject(
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
