/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#pragma once

#define AVrfHookShouldFaultInject(type) \
    AVrfShouldFaultInject(type, VerifierGetAppCallerAddress(_ReturnAddress()))

#define AVrfHookShouldVerifierStop() \
    AVrfShouldVerifierStop(VerifierGetAppCallerAddress(_ReturnAddress()))

#ifdef VFDYNF_HOOKS_PRIVATE
#define VFDYNF_ORIG_QUAL
#define VFDYNF_ORIG_INIT = NULL
#else
#define VFDYNF_ORIG_QUAL extern
#define VFDYNF_ORIG_INIT
#endif

#define VFDYNF_DECLAR_HOOK_TYPEDEF(ret, conv, name, params)                   \
    typedef ret conv Func_##name params;                                      \
    typedef Func_##name* PFunc_##name;

#define VFDYNF_DECLARE_HOOK(ret, conv, name, params)                          \
    ret conv Hook_##name params;                             \
    VFDYNF_ORIG_QUAL ret (conv *Orig_##name) params VFDYNF_ORIG_INIT;         \
    VFDYNF_DECLAR_HOOK_TYPEDEF(ret, conv, name, params)

#define VFDYNF_DECLARE_HOOK_EX(mod, conv, ret, name, params)                  \
    ret conv Hook_##mod##_##name params;                                      \
    VFDYNF_ORIG_QUAL ret (conv *Orig_##mod##_##name) params VFDYNF_ORIG_INIT;

#define VFDYNF_DECLARE_HOOK_K32BASE(ret, conv, name, params)                  \
    VFDYNF_DECLARE_HOOK_EX(Kernel32, conv, ret, name, params);                \
    VFDYNF_DECLARE_HOOK_EX(KernelBase, conv, ret, name, params)               \
    VFDYNF_DECLAR_HOOK_TYPEDEF(ret, conv, name, params)

#define VFDYNF_DECLARE_HOOK_K32BASEADV(ret, conv, name, params)               \
    VFDYNF_DECLARE_HOOK_EX(Kernel32, conv, ret, name, params);                \
    VFDYNF_DECLARE_HOOK_EX(KernelBase, conv, ret, name, params);              \
    VFDYNF_DECLARE_HOOK_EX(Advapi32, conv, ret, name, params)                 \
    VFDYNF_DECLAR_HOOK_TYPEDEF(ret, conv, name, params)

#define VFDYNF_LINK_COMMON_HOOK(mod, name, ...)                               \
    Hook_Common_##name(Orig_##mod##_##name, __VA_ARGS__)

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtCreateEvent, (
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtOpenEvent, (
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
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
NTAPI,
NtOpenFile, (
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtReadFile, (
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtQueryInformationFile, (
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtQueryVolumeInformationFile, (
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FSINFOCLASS FsInformationClass
    ));

VFDYNF_DECLARE_HOOK(
BSTR,
WINAPI,
SysAllocString, (
    _In_opt_z_ const OLECHAR* psz
    ));

VFDYNF_DECLARE_HOOK(
INT,
WINAPI,
SysReAllocString, (
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(_String_length_(psz) + 1)) BSTR* pbstr,
    _In_opt_z_ const OLECHAR* psz
    ));

VFDYNF_DECLARE_HOOK(
BSTR,
WINAPI,
SysAllocStringLen, (
    _In_reads_opt_(ui) const OLECHAR* strIn,
    UINT ui
    ));

VFDYNF_DECLARE_HOOK(
INT,
WINAPI,
SysReAllocStringLen, (
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(len + 1)) BSTR* pbstr,
    _In_opt_z_ const OLECHAR* psz,
    _In_ unsigned int len
    ));

VFDYNF_DECLARE_HOOK(
BSTR,
WINAPI,
SysAllocStringByteLen, (
    _In_opt_z_ LPCSTR psz,
    _In_ UINT len
    ));

VFDYNF_DECLARE_HOOK(
PVOID,
NTAPI,
RtlAllocateHeap, (
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    ));

VFDYNF_DECLARE_HOOK(
PVOID,
NTAPI,
RtlReAllocateHeap, (
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HGLOBAL,
WINAPI,
GlobalAlloc, (
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HGLOBAL,
WINAPI,
GlobalReAlloc, (
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HLOCAL,
WINAPI,
LocalAlloc, (
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HLOCAL,
WINAPI,
LocalReAlloc, (
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
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
NTAPI,
NtOpenKey, (
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
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
NTAPI,
NtQueryKey, (
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtQueryValueKey, (
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtQueryMultipleValueKey, (
    _In_ HANDLE KeyHandle,
    _Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
    _In_ ULONG EntryCount,
    _Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
    _Inout_ PULONG BufferLength,
    _Out_opt_ PULONG RequiredBufferLength
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtEnumerateKey, (
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtEnumerateValueKey, (
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
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
NTAPI,
NtOpenSection, (
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
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
NTAPI,
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
NTAPI,
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
NTAPI,
NtUnmapViewOfSection, (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtUnmapViewOfSectionEx, (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
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
NTAPI,
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
NTAPI,
NtWaitForSingleObject, (
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NTAPI,
NtWaitForMultipleObjects, (
    _In_ ULONG Count,
    _In_reads_(Count) HANDLE Handles[],
    _In_ WAIT_TYPE WaitType,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
CreateFileA, (
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
CreateFileW, (
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
WINAPI,
ReadFile, (
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
WINAPI,
ReadFileEx, (
    _In_ HANDLE hFile,
    _Out_writes_bytes_opt_(nNumberOfBytesToRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Inout_ LPOVERLAPPED lpOverlapped,
    _In_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
WINAPI,
GetFileInformationByHandle, (
    _In_ HANDLE hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WINAPI,
GetFileSize, (
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
WINAPI,
GetFileSizeEx, (
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WINAPI,
WaitForSingleObject, (
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WINAPI,
WaitForSingleObjectEx, (
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WINAPI,
WaitForMultipleObjects, (
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WINAPI,
WaitForMultipleObjectsEx, (
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
CreateEventA, (
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
CreateEventW, (
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
OpenEventA, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
OpenEventW, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegCreateKeyA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegCreateKeyW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegCreateKeyExA, (
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegCreateKeyExW, (
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegOpenKeyA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegOpenKeyW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegOpenKeyExA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegOpenKeyExW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegSetValueA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegSetValueW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegSetValueExA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegSetValueExW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegQueryValueA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegQueryValueW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegQueryMultipleValuesA, (
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegQueryMultipleValuesW, (
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegQueryValueExA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegQueryValueExW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegGetValueA, (
    _In_ HKEY hkey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValue,
    _In_ DWORD dwFlags,
    _Out_opt_ LPDWORD pdwType,
    _When_((dwFlags & 0x7F) == RRF_RT_REG_SZ ||
               (dwFlags & 0x7F) == RRF_RT_REG_EXPAND_SZ ||
               (dwFlags & 0x7F) == (RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ) ||
               *pdwType == REG_SZ ||
               *pdwType == REG_EXPAND_SZ, _Post_z_)
        _When_((dwFlags & 0x7F) == RRF_RT_REG_MULTI_SZ ||
               *pdwType == REG_MULTI_SZ, _Post_ _NullNull_terminated_)
    _Out_writes_bytes_to_opt_(*pcbData,*pcbData) PVOID pvData,
    _Inout_opt_ LPDWORD pcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegGetValueW, (
    _In_ HKEY hkey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValue,
    _In_ DWORD dwFlags,
    _Out_opt_ LPDWORD pdwType,
    _When_((dwFlags & 0x7F) == RRF_RT_REG_SZ ||
               (dwFlags & 0x7F) == RRF_RT_REG_EXPAND_SZ ||
               (dwFlags & 0x7F) == (RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ) ||
               *pdwType == REG_SZ ||
               *pdwType == REG_EXPAND_SZ, _Post_z_)
        _When_((dwFlags & 0x7F) == RRF_RT_REG_MULTI_SZ ||
               *pdwType == REG_MULTI_SZ, _Post_ _NullNull_terminated_)
    _Out_writes_bytes_to_opt_(*pcbData,*pcbData) PVOID pvData,
    _Inout_opt_ LPDWORD pcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegEnumKeyA, (
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegEnumKeyW, (
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegEnumKeyExA, (
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegEnumKeyExW, (
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegEnumValueA, (
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
APIENTRY,
RegEnumValueW, (
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
CreateFileMappingW, (
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
CreateFileMappingA, (
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
OpenFileMappingW, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
WINAPI,
OpenFileMappingA, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
WINAPI,
MapViewOfFile, (
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
WINAPI,
MapViewOfFileEx, (
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
WINAPI,
UnmapViewOfFile, (
    _In_ LPCVOID lpBaseAddress
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
WINAPI,
UnmapViewOfFileEx, (
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
WINAPI,
VirtualAlloc, (
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
WINAPI,
VirtualAllocEx, (
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    ));

VFDYNF_DECLARE_HOOK(
int,
WSAAPI,
WSARecv, (
    _In_ SOCKET s,
    _In_reads_(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
    _In_ DWORD dwBufferCount,
    _Out_opt_ LPDWORD lpNumberOfBytesRecvd,
    _Inout_ LPDWORD lpFlags,
    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    ));

VFDYNF_DECLARE_HOOK(
int,
WSAAPI,
WSARecvFrom, (
    _In_ SOCKET s,
    _In_reads_(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
    _In_ DWORD dwBufferCount,
    _Out_opt_ LPDWORD lpNumberOfBytesRecvd,
    _Inout_ LPDWORD lpFlags,
    _Out_writes_bytes_to_opt_(*lpFromlen,*lpFromlen) struct sockaddr FAR * lpFrom,
    _Inout_opt_ LPINT lpFromlen,
    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    ));

VFDYNF_DECLARE_HOOK(
int,
WSAAPI,
recv, (
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
    _In_ int len,
    _In_ int flags
    ));

VFDYNF_DECLARE_HOOK(
int,
WSAAPI,
recvfrom, (
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
    _In_ int len,
    _In_ int flags,
    _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR * from,
    _Inout_opt_ int FAR * fromlen
    ));
