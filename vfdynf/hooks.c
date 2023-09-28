/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

#define VFDYNF_DECLARE_HOOK(returnType, name, params) \
    returnType NTAPI Hook_##name params;\
    static returnType (NTAPI *Orig_##name) params = NULL;

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtCreateEvent, (
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtOpenEvent, (
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtCreateFile, (
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtOpenFile, (
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
    ));

VFDYNF_DECLARE_HOOK(
BSTR,
SysAllocString, (
    _In_opt_z_ const OLECHAR* psz
    ));

VFDYNF_DECLARE_HOOK(
INT,
SysReAllocString, (
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(_String_length_(psz) + 1)) BSTR* pbstr,
    _In_opt_z_ const OLECHAR* psz
    ));

VFDYNF_DECLARE_HOOK(
BSTR,
SysAllocStringLen, (
    _In_reads_opt_(ui) const OLECHAR* strIn,
    UINT ui
    ));

VFDYNF_DECLARE_HOOK(
INT,
SysReAllocStringLen, (
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(len + 1)) BSTR* pbstr,
    _In_opt_z_ const OLECHAR* psz,
    _In_ unsigned int len
    ));

VFDYNF_DECLARE_HOOK(
BSTR,
SysAllocStringByteLen, (
    _In_opt_z_ LPCSTR psz,
    _In_ UINT len
    ));

VFDYNF_DECLARE_HOOK(
PVOID,
RtlAllocateHeap, (
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    ));

VFDYNF_DECLARE_HOOK(
PVOID,
RtlReAllocateHeap, (
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size
    ));

VFDYNF_DECLARE_HOOK(
HGLOBAL,
GlobalAlloc, (
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    ));

VFDYNF_DECLARE_HOOK(
HGLOBAL,
GlobalReAlloc, (
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    ));

VFDYNF_DECLARE_HOOK(
HLOCAL,
LocalAlloc, (
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    ));

VFDYNF_DECLARE_HOOK(
HLOCAL,
LocalReAlloc, (
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtCreateKey, (
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtOpenKey, (
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtSetValueKey, (
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtCreateSection, (
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtOpenSection, (
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtCreateSectionEx, (
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtMapViewOfSection, (
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtMapViewOfSectionEx, (
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtAllocateVirtualMemory, (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtAllocateVirtualMemoryEx, (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtWaitForSingleObject, (
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtWaitForMultipleObjects, (
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    ));

#define VFDYNF_THUNK(x) { #x, NULL, Hook_##x }

#pragma warning(push)
#pragma warning(disable : 4152)

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpNtdll[] =
{
    VFDYNF_THUNK(NtOpenFile),
    VFDYNF_THUNK(NtCreateFile),
    VFDYNF_THUNK(RtlAllocateHeap),
    VFDYNF_THUNK(RtlReAllocateHeap),
    VFDYNF_THUNK(NtCreateEvent),
    VFDYNF_THUNK(NtOpenEvent),
    VFDYNF_THUNK(NtCreateKey),
    VFDYNF_THUNK(NtOpenKey),
    VFDYNF_THUNK(NtSetValueKey),
    VFDYNF_THUNK(NtAllocateVirtualMemory),
    VFDYNF_THUNK(NtAllocateVirtualMemoryEx),
    VFDYNF_THUNK(NtCreateSection),
    VFDYNF_THUNK(NtOpenSection),
    VFDYNF_THUNK(NtMapViewOfSection),
    VFDYNF_THUNK(NtMapViewOfSectionEx),
    { NULL, 0, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpKernel32[] =
{
    VFDYNF_THUNK(GlobalAlloc),
    VFDYNF_THUNK(GlobalReAlloc),
    VFDYNF_THUNK(LocalAlloc),
    VFDYNF_THUNK(LocalReAlloc),
    { NULL, 0, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpOleAut32[] =
{
    VFDYNF_THUNK(SysAllocString),
    VFDYNF_THUNK(SysReAllocString),
    VFDYNF_THUNK(SysAllocStringLen),
    VFDYNF_THUNK(SysReAllocStringLen),
    VFDYNF_THUNK(SysAllocStringByteLen),
    { NULL, 0, NULL }
};

#pragma warning(pop)

RTL_VERIFIER_DLL_DESCRIPTOR AVrfDllDescriptors[] =
{
    { L"ntdll.dll",    0, NULL, AVrfpNtdll },
    { L"kernel32.dll", 0, NULL, AVrfpKernel32 },
    { L"oleaut32.dll", 0, NULL, AVrfpOleAut32 },
    { NULL,            0, NULL, NULL }
};

typedef struct _VFDYNF_HOOK_LINK_ENTRY
{
    PVOID* Store;
    PVOID* Load;
} VFDYNF_HOOK_LINK_ENTRY, *PVFDYNF_HOOK_LINK_ENTRY;

BOOLEAN AVrfpLinkHook(
    _In_ PRTL_VERIFIER_THUNK_DESCRIPTOR Thunks,
    _In_ PVOID Hook,
    _Out_ PVOID* Orig
    )
{
    for (PRTL_VERIFIER_THUNK_DESCRIPTOR thunk = Thunks;
         thunk->ThunkName;
         thunk = thunk + 1)
    {
        if (thunk->ThunkNewAddress == Hook)
        {
            *Orig = thunk->ThunkOldAddress;
            return TRUE;
        }
    }

    *Orig = NULL;
    return FALSE;
}

#define AVrfLinkHook(thunks, x)                                               \
    if (!AVrfpLinkHook(thunks, (PVOID)Hook_##x, (PVOID*)&Orig_##x))           \
    {                                                                         \
        return FALSE;                                                         \
    }

BOOLEAN AVrfHookProcessAttach(
    VOID
    )
{
    AVrfLinkHook(AVrfpNtdll, NtOpenFile);
    AVrfLinkHook(AVrfpNtdll, NtCreateFile);
    AVrfLinkHook(AVrfpNtdll, RtlAllocateHeap);
    AVrfLinkHook(AVrfpNtdll, RtlReAllocateHeap);
    AVrfLinkHook(AVrfpNtdll, NtCreateEvent);
    AVrfLinkHook(AVrfpNtdll, NtOpenEvent);
    AVrfLinkHook(AVrfpNtdll, NtCreateKey);
    AVrfLinkHook(AVrfpNtdll, NtOpenKey);
    AVrfLinkHook(AVrfpNtdll, NtSetValueKey);
    AVrfLinkHook(AVrfpNtdll, NtAllocateVirtualMemory);
    AVrfLinkHook(AVrfpNtdll, NtAllocateVirtualMemoryEx);
    AVrfLinkHook(AVrfpNtdll, NtCreateSection);
    AVrfLinkHook(AVrfpNtdll, NtOpenSection);
    AVrfLinkHook(AVrfpNtdll, NtMapViewOfSection);
    AVrfLinkHook(AVrfpNtdll, NtMapViewOfSectionEx);

    AVrfLinkHook(AVrfpKernel32, GlobalAlloc);
    AVrfLinkHook(AVrfpKernel32, GlobalReAlloc);
    AVrfLinkHook(AVrfpKernel32, LocalAlloc);
    AVrfLinkHook(AVrfpKernel32, LocalReAlloc);

    AVrfLinkHook(AVrfpOleAut32, SysAllocString);
    AVrfLinkHook(AVrfpOleAut32, SysReAllocString);
    AVrfLinkHook(AVrfpOleAut32, SysAllocStringLen);
    AVrfLinkHook(AVrfpOleAut32, SysReAllocStringLen);
    AVrfLinkHook(AVrfpOleAut32, SysAllocStringByteLen);

    return TRUE;
}

BOOLEAN AVrfpHookShouldFaultInject(
    _In_ ULONG FaultType,
    _In_opt_ _Maybenull_ PVOID CallerAddress
    )
{
    BOOLEAN result;
    ULONG recursionCount;

    result = FALSE;

    recursionCount = AVrfLayerGetRecursionCount();
    if (!recursionCount)
    {
        AVrfLayerSetRecursionCount(recursionCount + 1);

        result = AvrfShouldFaultInject(FaultType, CallerAddress);

        AVrfLayerSetRecursionCount(recursionCount);
    }

    return result;
}

#define AVrfHookShouldFaultInject(type) \
    AVrfpHookShouldFaultInject(type, VerifierGetAppCallerAddress(_ReturnAddress()))

NTSTATUS
NTAPI
Hook_NtCreateEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateEvent(EventHandle,
                              DesiredAccess,
                              ObjectAttributes,
                              EventType,
                              InitialState);
}

NTSTATUS
NTAPI
Hook_NtOpenEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS
NTAPI
Hook_NtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FILE))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateFile(FileHandle,
                             DesiredAccess,
                             ObjectAttributes,
                             IoStatusBlock,
                             AllocationSize,
                             FileAttributes,
                             ShareAccess,
                             CreateDisposition,
                             CreateOptions,
                             EaBuffer,
                             EaLength);
}

NTSTATUS
NTAPI
Hook_NtOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FILE))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtOpenFile(FileHandle,
                           DesiredAccess,
                           ObjectAttributes,
                           IoStatusBlock,
                           ShareAccess,
                           OpenOptions);
}

BSTR
WINAPI
Hook_SysAllocString(
    _In_opt_z_ const OLECHAR * psz
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_OLE))
    {
        return NULL;
    }

    return Orig_SysAllocString(psz);
}

INT
WINAPI
Hook_SysReAllocString(
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(_String_length_(psz)+1)) BSTR* pbstr,
    _In_opt_z_ const OLECHAR* psz
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_OLE))
    {
        return 0;
    }

    return Orig_SysReAllocString(pbstr, psz);
}

BSTR
WINAPI
Hook_SysAllocStringLen(
    _In_reads_opt_(ui) const OLECHAR * strIn,
    UINT ui
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_OLE))
    {
        return NULL;
    }

    return Orig_SysAllocStringLen(strIn, ui);
}

INT
WINAPI
Hook_SysReAllocStringLen(
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(len+1)) BSTR* pbstr,
    _In_opt_z_ const OLECHAR* psz,
    _In_ unsigned int len
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_OLE))
    {
        return 0;
    }

    return Orig_SysReAllocStringLen(pbstr, psz, len);
}

BSTR
WINAPI
Hook_SysAllocStringByteLen(
    _In_opt_z_ LPCSTR psz,
    _In_ UINT len
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_OLE))
    {
        return NULL;
    }

    return Orig_SysAllocStringByteLen(psz, len);
}

PVOID
NTAPI
Hook_RtlAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_RtlAllocateHeap(HeapHandle, Flags, Size);
}

PVOID
NTAPI
Hook_RtlReAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_RtlReAllocateHeap(HeapHandle, Flags, BaseAddress, Size);
}

HGLOBAL
WINAPI
Hook_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_GlobalAlloc(uFlags, dwBytes);
}

HGLOBAL
WINAPI
Hook_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_GlobalReAlloc(hMem, dwBytes, uFlags);
}

HLOCAL
WINAPI
Hook_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_LocalAlloc(uFlags, uBytes);
}

HLOCAL
WINAPI
Hook_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_LocalReAlloc(hMem, uBytes, uFlags);
}

NTSTATUS
NTAPI
Hook_NtCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateKey(KeyHandle,
                            DesiredAccess,
                            ObjectAttributes,
                            TitleIndex,
                            Class,
                            CreateOptions,
                            Disposition);
}

NTSTATUS
NTAPI
Hook_NtOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS
NTAPI
Hook_NtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtSetValueKey(KeyHandle,
                              ValueName,
                              TitleIndex,
                              Type,
                              Data,
                              DataSize);
}

NTSTATUS
NTAPI
Hook_NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateSection(SectionHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                MaximumSize,
                                SectionPageProtection,
                                AllocationAttributes,
                                FileHandle);
}

NTSTATUS
NTAPI
Hook_NtCreateSectionEx(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtCreateSectionEx(SectionHandle,
                                  DesiredAccess,
                                  ObjectAttributes,
                                  MaximumSize,
                                  SectionPageProtection,
                                  AllocationAttributes,
                                  FileHandle,
                                  ExtendedParameters,
                                  ExtendedParameterCount);
}

NTSTATUS
NTAPI
Hook_NtOpenSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS
NTAPI
Hook_NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtMapViewOfSection(SectionHandle,
                                   ProcessHandle,
                                   BaseAddress,
                                   ZeroBits,
                                   CommitSize,
                                   SectionOffset,
                                   ViewSize,
                                   InheritDisposition,
                                   AllocationType,
                                   Win32Protect);
}

NTSTATUS
NTAPI
Hook_NtMapViewOfSectionEx(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    return Orig_NtMapViewOfSectionEx(SectionHandle,
                                     ProcessHandle,
                                     BaseAddress,
                                     SectionOffset,
                                     ViewSize,
                                     AllocationType,
                                     Win32Protect,
                                     ExtendedParameters,
                                     ExtendedParameterCount);
}

NTSTATUS
NTAPI
Hook_NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return Orig_NtAllocateVirtualMemory(ProcessHandle,
                                        BaseAddress,
                                        ZeroBits,
                                        RegionSize,
                                        AllocationType,
                                        Protect);
}

NTSTATUS
NTAPI
Hook_NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return Orig_NtAllocateVirtualMemoryEx(ProcessHandle,
                                          BaseAddress,
                                          RegionSize,
                                          AllocationType,
                                          PageProtection,
                                          ExtendedParameters,
                                          ExtendedParameterCount);
}

NTSTATUS
NTAPI
Hook_NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return STATUS_TIMEOUT;
    }

    return Orig_NtWaitForSingleObject(Handle, Alertable, Timeout);
}

NTSTATUS
NTAPI
Hook_NtWaitForMultipleObjects(
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return STATUS_TIMEOUT;
    }

    return Orig_NtWaitForMultipleObjects(Count,
                                         Handles,
                                         WaitType,
                                         Alertable,
                                         Timeout);
}
