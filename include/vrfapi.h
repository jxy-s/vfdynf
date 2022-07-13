/*
    Undocumented or partially documented application verifier APIs.

    Author: Johnny Shaw
*/
#pragma once
#include <minwindef.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

#define DLL_PROCESS_VERIFIER 4

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR
{
    PCSTR ThunkName;
    PVOID ThunkOldAddress;
    PVOID ThunkNewAddress;

} RTL_VERIFIER_THUNK_DESCRIPTOR, * PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR
{
    PCWSTR DllName;
    DWORD DllFlags;
    PVOID DllAddress;
    PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;

} RTL_VERIFIER_DLL_DESCRIPTOR, * PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef
void
(NTAPI * RTL_VERIFIER_DLL_LOAD_CALLBACK)(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    );

typedef
void
(NTAPI * RTL_VERIFIER_DLL_UNLOAD_CALLBACK)(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    );

typedef
void
(NTAPI * RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK)(
    _In_ PVOID AllocationBase,
    _In_ SIZE_T AllocationSize
    );

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR
{
    //
    // Filled by verifier provider DLL
    //

    DWORD Length;
    PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
    RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
    RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
    
    //
    // Filled by verifier engine
    //

    PCWSTR VerifierImage;
    DWORD VerifierFlags;
    DWORD VerifierDebug;
    PVOID RtlpGetStackTraceAddress;
    PVOID RtlpDebugPageHeapCreate;
    PVOID RtlpDebugPageHeapDestroy;

    //
    // Filled by verifier provider DLL
    //

    RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;

} RTL_VERIFIER_PROVIDER_DESCRIPTOR, * PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

NTSYSAPI
NTSTATUS
NTAPI
VerifierRegisterProvider(
    _In_ HMODULE Module,
    _Inout_ PRTL_VERIFIER_PROVIDER_DESCRIPTOR Registeration
    );

typedef enum _AVRF_PROPERTY_TYPE
{
    AVRF_PROPERTY_NONE = 0x0,
    AVRF_PROPERTY_DWORD = 0x4,
    AVRF_PROPERTY_QWORD = 0xB,
    AVRF_PROPERTY_SZ = 0x1,
    AVRF_PROPERTY_MULTI_SZ = 0x7,
    AVRF_PROPERTY_BINARY = 0x3,
    AVRF_PROPERTY_BOOLEAN = 0x100,
    AVRF_PROPERTY_DEFAULT = 0x101,

} AVRF_PROPERTY_TYPE;

typedef struct _AVRF_PROPERTY_DESCRIPTOR
{
    AVRF_PROPERTY_TYPE Type;
    PCWSTR Name;
    PVOID Address;
    SIZE_T Size;
    PCWSTR Description;
    PVOID Param;

} AVRF_PROPERTY_DESCRIPTOR, * PAVRF_PROPERTY_DESCRIPTOR;

struct _AVRF_LAYER_DESCRIPTOR;
typedef _AVRF_LAYER_DESCRIPTOR AVRF_LAYER_DESCRIPTOR;
typedef _AVRF_LAYER_DESCRIPTOR* PAVRF_LAYER_DESCRIPTOR;

typedef struct _AVRF_BREAK_DESCRIPTOR
{
    DWORD StopCode;
    DWORD ErrorReport;
    DWORD Severity;
    DWORD Flavor;
    PCWSTR Message;
    DWORD MessageResourceId;
    PCWSTR Param1Descr;
    DWORD Param1DescrResourceId;
    PCWSTR Param2Descr;
    DWORD Param2DescrResourceId;
    PCWSTR Param3Descr;
    DWORD Param3DescrResourceId;
    PCWSTR Param4Descr;
    DWORD Param4DescrResourceId;
    PCWSTR FormatString;
    DWORD FormatStringResourceId;
    PCWSTR Description;
    DWORD DescriptionResourceId;
    PAVRF_LAYER_DESCRIPTOR LayerDescriptor;

} AVRF_BREAK_DESCRIPTOR, * PAVRF_BREAK_DESCRIPTOR;

//
// Application verifier standard flags
//

#define RTL_VRF_FLG_FULL_PAGE_HEAP                   0x00000001
#define RTL_VRF_FLG_RESERVED_DONOTUSE                0x00000002 // old RTL_VRF_FLG_LOCK_CHECKS
#define RTL_VRF_FLG_HANDLE_CHECKS                    0x00000004
#define RTL_VRF_FLG_STACK_CHECKS                     0x00000008
#define RTL_VRF_FLG_APPCOMPAT_CHECKS                 0x00000010
#define RTL_VRF_FLG_TLS_CHECKS                       0x00000020
#define RTL_VRF_FLG_DIRTY_STACKS                     0x00000040
#define RTL_VRF_FLG_RPC_CHECKS                       0x00000080
#define RTL_VRF_FLG_COM_CHECKS                       0x00000100
#define RTL_VRF_FLG_DANGEROUS_APIS                   0x00000200
#define RTL_VRF_FLG_RACE_CHECKS                      0x00000400
#define RTL_VRF_FLG_DEADLOCK_CHECKS                  0x00000800
#define RTL_VRF_FLG_FIRST_CHANCE_EXCEPTION_CHECKS    0x00001000
#define RTL_VRF_FLG_VIRTUAL_MEM_CHECKS               0x00002000
#define RTL_VRF_FLG_ENABLE_LOGGING                   0x00004000
#define RTL_VRF_FLG_FAST_FILL_HEAP                   0x00008000
#define RTL_VRF_FLG_VIRTUAL_SPACE_TRACKING           0x00010000
#define RTL_VRF_FLG_ENABLED_SYSTEM_WIDE              0x00020000
#define RTL_VRF_FLG_MISCELLANEOUS_CHECKS             0x00020000
#define RTL_VRF_FLG_LOCK_CHECKS                      0x00040000

//
// Application verifier standard stop codes
//

#define APPLICATION_VERIFIER_INTERNAL_ERROR               0x80000000
#define APPLICATION_VERIFIER_INTERNAL_WARNING             0x40000000
#define APPLICATION_VERIFIER_NO_BREAK                     0x20000000
#define APPLICATION_VERIFIER_CONTINUABLE_BREAK            0x10000000

#define APPLICATION_VERIFIER_UNKNOWN_ERROR                    0x0001
#define APPLICATION_VERIFIER_ACCESS_VIOLATION                 0x0002
#define APPLICATION_VERIFIER_UNSYNCHRONIZED_ACCESS            0x0003
#define APPLICATION_VERIFIER_EXTREME_SIZE_REQUEST             0x0004
#define APPLICATION_VERIFIER_BAD_HEAP_HANDLE                  0x0005
#define APPLICATION_VERIFIER_SWITCHED_HEAP_HANDLE             0x0006
#define APPLICATION_VERIFIER_DOUBLE_FREE                      0x0007
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK             0x0008
#define APPLICATION_VERIFIER_DESTROY_PROCESS_HEAP             0x0009
#define APPLICATION_VERIFIER_UNEXPECTED_EXCEPTION             0x000A
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_EXCEPTION_RAISED_FOR_HEADER 0x000B
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_EXCEPTION_RAISED_FOR_PROBING 0x000C
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_HEADER      0x000D
#define APPLICATION_VERIFIER_CORRUPTED_FREED_HEAP_BLOCK       0x000E
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_SUFFIX      0x000F
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_START_STAMP 0x0010
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_END_STAMP   0x0011
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_PREFIX      0x0012
#define APPLICATION_VERIFIER_FIRST_CHANCE_ACCESS_VIOLATION    0x0013
#define APPLICATION_VERIFIER_CORRUPTED_HEAP_LIST              0x0014

#define APPLICATION_VERIFIER_TERMINATE_THREAD_CALL        0x0100
#define APPLICATION_VERIFIER_STACK_OVERFLOW               0x0101
#define APPLICATION_VERIFIER_INVALID_EXIT_PROCESS_CALL    0x0102

#define APPLICATION_VERIFIER_EXIT_THREAD_OWNS_LOCK        0x0200
#define APPLICATION_VERIFIER_LOCK_IN_UNLOADED_DLL         0x0201
#define APPLICATION_VERIFIER_LOCK_IN_FREED_HEAP           0x0202
#define APPLICATION_VERIFIER_LOCK_DOUBLE_INITIALIZE       0x0203
#define APPLICATION_VERIFIER_LOCK_IN_FREED_MEMORY         0x0204
#define APPLICATION_VERIFIER_LOCK_CORRUPTED               0x0205
#define APPLICATION_VERIFIER_LOCK_INVALID_OWNER           0x0206
#define APPLICATION_VERIFIER_LOCK_INVALID_RECURSION_COUNT 0x0207
#define APPLICATION_VERIFIER_LOCK_INVALID_LOCK_COUNT      0x0208
#define APPLICATION_VERIFIER_LOCK_OVER_RELEASED           0x0209
#define APPLICATION_VERIFIER_LOCK_NOT_INITIALIZED         0x0210
#define APPLICATION_VERIFIER_LOCK_ALREADY_INITIALIZED     0x0211
#define APPLICATION_VERIFIER_LOCK_IN_FREED_VMEM           0x0212
#define APPLICATION_VERIFIER_LOCK_IN_UNMAPPED_MEM         0x0213
#define APPLICATION_VERIFIER_THREAD_NOT_LOCK_OWNER        0x0214

#define APPLICATION_VERIFIER_INVALID_HANDLE               0x0300
#define APPLICATION_VERIFIER_INVALID_TLS_VALUE            0x0301
#define APPLICATION_VERIFIER_INCORRECT_WAIT_CALL          0x0302
#define APPLICATION_VERIFIER_NULL_HANDLE                  0x0303
#define APPLICATION_VERIFIER_WAIT_IN_DLLMAIN              0x0304

#define APPLICATION_VERIFIER_COM_ERROR                    0x0400
#define APPLICATION_VERIFIER_COM_API_IN_DLLMAIN           0x0401
#define APPLICATION_VERIFIER_COM_UNHANDLED_EXCEPTION      0x0402
#define APPLICATION_VERIFIER_COM_UNBALANCED_COINIT        0x0403
#define APPLICATION_VERIFIER_COM_UNBALANCED_OLEINIT       0x0404
#define APPLICATION_VERIFIER_COM_UNBALANCED_SWC           0x0405
#define APPLICATION_VERIFIER_COM_NULL_DACL                0x0406
#define APPLICATION_VERIFIER_COM_UNSAFE_IMPERSONATION     0x0407
#define APPLICATION_VERIFIER_COM_SMUGGLED_WRAPPER         0x0408
#define APPLICATION_VERIFIER_COM_SMUGGLED_PROXY           0x0409
#define APPLICATION_VERIFIER_COM_CF_SUCCESS_WITH_NULL     0x040A
#define APPLICATION_VERIFIER_COM_GCO_SUCCESS_WITH_NULL    0x040B
#define APPLICATION_VERIFIER_COM_OBJECT_IN_FREED_MEMORY   0x040C
#define APPLICATION_VERIFIER_COM_OBJECT_IN_UNLOADED_DLL   0x040D
#define APPLICATION_VERIFIER_COM_VTBL_IN_FREED_MEMORY     0x040E
#define APPLICATION_VERIFIER_COM_VTBL_IN_UNLOADED_DLL     0x040F
#define APPLICATION_VERIFIER_COM_HOLDING_LOCKS_ON_CALL    0x0410

#define APPLICATION_VERIFIER_RPC_ERROR                    0x0500

#define APPLICATION_VERIFIER_INVALID_FREEMEM              0x0600
#define APPLICATION_VERIFIER_INVALID_ALLOCMEM             0x0601
#define APPLICATION_VERIFIER_INVALID_MAPVIEW              0x0602
#define APPLICATION_VERIFIER_PROBE_INVALID_ADDRESS        0x0603
#define APPLICATION_VERIFIER_PROBE_FREE_MEM               0x0604
#define APPLICATION_VERIFIER_PROBE_GUARD_PAGE             0x0605
#define APPLICATION_VERIFIER_PROBE_NULL                   0x0606
#define APPLICATION_VERIFIER_PROBE_INVALID_START_OR_SIZE  0x0607
#define APPLICATION_VERIFIER_SIZE_HEAP_UNEXPECTED_EXCEPTION 0x0618


#define VERIFIER_STOP(Code, Msg, P1, S1, P2, S2, P3, S3, P4, S4) {  \
        RtlApplicationVerifierStop((Code),                         \
                                   (Msg),                          \
                                   (ULONG_PTR)(P1),(S1),           \
                                   (ULONG_PTR)(P2),(S2),           \
                                   (ULONG_PTR)(P3),(S3),           \
                                   (ULONG_PTR)(P4),(S4));          \
  }

VOID
NTAPI
RtlApplicationVerifierStop(
    _In_ ULONG_PTR Code,
    _In_ PSTR Message,
    _In_ ULONG_PTR Param1,
    _In_ PSTR Description1,
    _In_ ULONG_PTR Param2,
    _In_ PSTR Description2,
    _In_ ULONG_PTR Param3,
    _In_ PSTR Description3,
    _In_ ULONG_PTR Param4,
    _In_ PSTR Description4
    );

typedef
DWORD 
(NTAPI * AVRF_ENABLE_CALLBACK)(
    DWORD Unknown/*???*/
    );

typedef
DWORD 
(NTAPI * AVRF_PROPERTY_DESCRIPTOR_CALLBACK)(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Descriptor
    );

typedef struct _AVRF_LAYER_DESCRIPTOR
{
    PRTL_VERIFIER_PROVIDER_DESCRIPTOR Provider;
    PCWSTR LayerGuidString;
    PCWSTR LayerName;
    WORD VersionMajor;
    WORD VersionMinor;
    PAVRF_BREAK_DESCRIPTOR BreakDescriptors;
    PAVRF_PROPERTY_DESCRIPTOR PropertyDescriptors;
    PCWSTR LayerGroupName;
    PCWSTR Description;
    PCWSTR AlternativeLongLayerName;
    DWORD Flags;
    DWORD SqmBit;
    AVRF_ENABLE_CALLBACK EnableCallback;
    AVRF_PROPERTY_DESCRIPTOR_CALLBACK PropertyCallback;
    AVRF_PROPERTY_DESCRIPTOR_CALLBACK ValidateCallback;
    PVOID ReservedCallback;
    LIST_ENTRY Links;
    DWORD MinStopCode;
    DWORD MaxStopCode;
    PCWSTR ProviderImage;
    GUID LayerGuid;
    DWORD TlsIndex;
    DWORD Enabled;

} AVRF_LAYER_DESCRIPTOR, * PAVRF_LAYER_DESCRIPTOR;

NTSYSAPI
DWORD
NTAPI
VerifierRegisterLayer(
    _In_ HMODULE Module,
    _Inout_ PAVRF_LAYER_DESCRIPTOR Layer
    );

#define AVRF_LAYER_FLAG_TLS_SLOT ((UCHAR)(0x01))

NTSYSAPI
DWORD
NTAPI
VerifierRegisterLayerEx(
    _In_ HMODULE Module,
    _Inout_ PAVRF_LAYER_DESCRIPTOR Layer,
    _In_ UCHAR Flags
    );

NTSYSAPI
DWORD
NTAPI
VerifierUnregisterLayer(
    _In_ HMODULE Module,
    _In_ PAVRF_LAYER_DESCRIPTOR Layer
    );

NTSYSAPI
PVOID
CDECL
VerifierGetAppCallerAddress(
    _In_ PVOID ReturnAddress
    );

NTSYSAPI
BOOLEAN
NTAPI
VerifierShouldFaultInject(
    _In_ DWORD Class,
    _In_ PVOID CallerAddress
    );

NTSYSAPI
DWORD
NTAPI
VerifierRegisterFaultInjectProvider(
    _In_ DWORD Count,
    _Out_ PDWORD ClassBase 
    );

NTSYSAPI
DWORD
NTAPI
VerifierSetFaultInjectionProbability(
    _In_ DWORD Class,
    _In_ DWORD Probability
    );

NTSYSAPI
DWORD
NTAPI
VerifierSetAPIClassName(
    DWORD Class,
    PCWSTR Name
    );

NTSYSAPI
VOID
NTAPI
VerifierSetFaultInjectionSeed(
    DWORD Seed
    );

NTSYSAPI
DWORD
NTAPI
VerifierSuspendFaultInjection(
    DWORD TimeoutMs
    );

NTSYSAPI
DWORD
NTAPI
VerifierEnableFaultInjectionTargetRange(
    DWORD Class,
    PVOID StartAddress,
    PVOID EndAddress
    );

NTSYSAPI
DWORD
NTAPI
VerifierDisableFaultInjectionTargetRange(
    DWORD Class,
    PVOID StartAddress,
    PVOID EndAddress
    );

#ifdef __cplusplus
}
#endif // __cplusplus
