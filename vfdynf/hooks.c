/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

//
// N.B. Application verifier uses the thunks when patching call targets in the
// target binary and only the target binary. They effectively do IAT hooking.
// So we need to duplicate hook definitions for each possible import.
//

#define VFDYNF_DECLARE_HOOK(returnType, name, params)                         \
    returnType NTAPI Hook_##name params;                                      \
    static returnType (NTAPI *Orig_##name) params = NULL;

#define VFDYNF_DECLARE_HOOK_EX(mod, returnType, name, params)                 \
    returnType NTAPI Hook_##mod##_##name params;                              \
    static returnType (NTAPI *Orig_##mod##_##name) params = NULL;

#define VFDYNF_DECLARE_HOOK_K32BASE(returnType, name, params)                 \
    VFDYNF_DECLARE_HOOK_EX(Kernel32, returnType, name, params);               \
    VFDYNF_DECLARE_HOOK_EX(KernelBase, returnType, name, params)

#define VFDYNF_DECLARE_HOOK_K32BASEADV(returnType, name, params)              \
    VFDYNF_DECLARE_HOOK_EX(Kernel32, returnType, name, params);               \
    VFDYNF_DECLARE_HOOK_EX(KernelBase, returnType, name, params);             \
    VFDYNF_DECLARE_HOOK_EX(Advapi32, returnType, name, params)

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

VFDYNF_DECLARE_HOOK_K32BASE(
HGLOBAL,
GlobalAlloc, (
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HGLOBAL,
GlobalReAlloc, (
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HLOCAL,
LocalAlloc, (
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
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
NtUnmapViewOfSection, (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    ));

VFDYNF_DECLARE_HOOK(
NTSTATUS,
NtUnmapViewOfSectionEx, (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags
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

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
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
DWORD,
WaitForSingleObject, (
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WaitForSingleObjectEx, (
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WaitForMultipleObjects, (
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
DWORD,
WaitForMultipleObjectsEx, (
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
CreateEventA, (
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
CreateEventW, (
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
OpenEventA, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
OpenEventW, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegCreateKeyA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegCreateKeyW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
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
RegOpenKeyA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegOpenKeyW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegOpenKeyExA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegOpenKeyExW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegSetValueA, (
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
RegSetValueW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASEADV(
LSTATUS,
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
RegSetValueExW, (
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
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
OpenFileMappingW, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
HANDLE,
OpenFileMappingA, (
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
MapViewOfFile, (
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
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
UnmapViewOfFile, (
    _In_ LPCVOID lpBaseAddress
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
BOOL,
UnmapViewOfFileEx, (
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
VirtualAlloc, (
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    ));

VFDYNF_DECLARE_HOOK_K32BASE(
LPVOID,
VirtualAllocEx, (
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    ));

#define VFDYNF_THUNK(x) { #x, NULL, Hook_##x }
#define VFDYNF_THUNK_EX(n, x) { n, NULL, Hook_##x }

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
    VFDYNF_THUNK(NtUnmapViewOfSection),
    VFDYNF_THUNK(NtUnmapViewOfSectionEx),
    { NULL, 0, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpKernel32[] =
{
    VFDYNF_THUNK_EX("GlobalAlloc", Kernel32_GlobalAlloc),
    VFDYNF_THUNK_EX("GlobalReAlloc", Kernel32_GlobalReAlloc),
    VFDYNF_THUNK_EX("LocalAlloc", Kernel32_LocalAlloc),
    VFDYNF_THUNK_EX("LocalReAlloc", Kernel32_LocalReAlloc),
    VFDYNF_THUNK_EX("CreateFileA", Kernel32_CreateFileA),
    VFDYNF_THUNK_EX("CreateFileW", Kernel32_CreateFileW),
    VFDYNF_THUNK_EX("WaitForSingleObject", Kernel32_WaitForSingleObject),
    VFDYNF_THUNK_EX("WaitForSingleObjectEx", Kernel32_WaitForSingleObjectEx),
    VFDYNF_THUNK_EX("WaitForMultipleObjects", Kernel32_WaitForMultipleObjects),
    VFDYNF_THUNK_EX("WaitForMultipleObjectsEx", Kernel32_WaitForMultipleObjectsEx),
    VFDYNF_THUNK_EX("CreateEventA", Kernel32_CreateEventA),
    VFDYNF_THUNK_EX("CreateEventW", Kernel32_CreateEventW),
    VFDYNF_THUNK_EX("OpenEventA", Kernel32_OpenEventA),
    VFDYNF_THUNK_EX("OpenEventW", Kernel32_OpenEventW),
    VFDYNF_THUNK_EX("RegCreateKeyA", Kernel32_RegCreateKeyA),
    VFDYNF_THUNK_EX("RegCreateKeyW", Kernel32_RegCreateKeyW),
    VFDYNF_THUNK_EX("RegCreateKeyExA", Kernel32_RegCreateKeyExA),
    VFDYNF_THUNK_EX("RegCreateKeyExW", Kernel32_RegCreateKeyExW),
    VFDYNF_THUNK_EX("RegOpenKeyA", Kernel32_RegOpenKeyA),
    VFDYNF_THUNK_EX("RegOpenKeyW", Kernel32_RegOpenKeyW),
    VFDYNF_THUNK_EX("RegOpenKeyExA", Kernel32_RegOpenKeyExA),
    VFDYNF_THUNK_EX("RegOpenKeyExW", Kernel32_RegOpenKeyExW),
    VFDYNF_THUNK_EX("RegSetValueA", Kernel32_RegSetValueA),
    VFDYNF_THUNK_EX("RegSetValueW", Kernel32_RegSetValueW),
    VFDYNF_THUNK_EX("RegSetValueExA", Kernel32_RegSetValueExA),
    VFDYNF_THUNK_EX("RegSetValueExW", Kernel32_RegSetValueExW),
    VFDYNF_THUNK_EX("CreateFileMappingW", Kernel32_CreateFileMappingW),
    VFDYNF_THUNK_EX("CreateFileMappingA", Kernel32_CreateFileMappingA),
    VFDYNF_THUNK_EX("OpenFileMappingW", Kernel32_OpenFileMappingW),
    VFDYNF_THUNK_EX("OpenFileMappingA", Kernel32_OpenFileMappingA),
    VFDYNF_THUNK_EX("MapViewOfFile", Kernel32_MapViewOfFile),
    VFDYNF_THUNK_EX("MapViewOfFileEx", Kernel32_MapViewOfFileEx),
    VFDYNF_THUNK_EX("UnmapViewOfFile", Kernel32_UnmapViewOfFile),
    VFDYNF_THUNK_EX("UnmapViewOfFileEx", Kernel32_UnmapViewOfFileEx),
    VFDYNF_THUNK_EX("VirtualAlloc", Kernel32_VirtualAlloc),
    VFDYNF_THUNK_EX("VirtualAllocEx", Kernel32_VirtualAllocEx),
    { NULL, 0, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpKernelBase[] =
{
    VFDYNF_THUNK_EX("GlobalAlloc", KernelBase_GlobalAlloc),
    VFDYNF_THUNK_EX("GlobalReAlloc", KernelBase_GlobalReAlloc),
    VFDYNF_THUNK_EX("LocalAlloc", KernelBase_LocalAlloc),
    VFDYNF_THUNK_EX("LocalReAlloc", KernelBase_LocalReAlloc),
    VFDYNF_THUNK_EX("CreateFileA", KernelBase_CreateFileA),
    VFDYNF_THUNK_EX("CreateFileW", KernelBase_CreateFileW),
    VFDYNF_THUNK_EX("WaitForSingleObject", KernelBase_WaitForSingleObject),
    VFDYNF_THUNK_EX("WaitForSingleObjectEx", KernelBase_WaitForSingleObjectEx),
    VFDYNF_THUNK_EX("WaitForMultipleObjects", KernelBase_WaitForMultipleObjects),
    VFDYNF_THUNK_EX("WaitForMultipleObjectsEx", KernelBase_WaitForMultipleObjectsEx),
    VFDYNF_THUNK_EX("CreateEventA", KernelBase_CreateEventA),
    VFDYNF_THUNK_EX("CreateEventW", KernelBase_CreateEventW),
    VFDYNF_THUNK_EX("OpenEventA", KernelBase_OpenEventA),
    VFDYNF_THUNK_EX("OpenEventW", KernelBase_OpenEventW),
    VFDYNF_THUNK_EX("RegCreateKeyA", KernelBase_RegCreateKeyA),
    VFDYNF_THUNK_EX("RegCreateKeyW", KernelBase_RegCreateKeyW),
    VFDYNF_THUNK_EX("RegCreateKeyExA", KernelBase_RegCreateKeyExA),
    VFDYNF_THUNK_EX("RegCreateKeyExW", KernelBase_RegCreateKeyExW),
    VFDYNF_THUNK_EX("RegOpenKeyA", KernelBase_RegOpenKeyA),
    VFDYNF_THUNK_EX("RegOpenKeyW", KernelBase_RegOpenKeyW),
    VFDYNF_THUNK_EX("RegOpenKeyExA", KernelBase_RegOpenKeyExA),
    VFDYNF_THUNK_EX("RegOpenKeyExW", KernelBase_RegOpenKeyExW),
    VFDYNF_THUNK_EX("RegSetValueA", KernelBase_RegSetValueA),
    VFDYNF_THUNK_EX("RegSetValueW", KernelBase_RegSetValueW),
    VFDYNF_THUNK_EX("RegSetValueExA", KernelBase_RegSetValueExA),
    VFDYNF_THUNK_EX("RegSetValueExW", KernelBase_RegSetValueExW),
    VFDYNF_THUNK_EX("CreateFileMappingW", KernelBase_CreateFileMappingW),
    VFDYNF_THUNK_EX("CreateFileMappingA", KernelBase_CreateFileMappingA),
    VFDYNF_THUNK_EX("OpenFileMappingW", KernelBase_OpenFileMappingW),
    VFDYNF_THUNK_EX("OpenFileMappingA", KernelBase_OpenFileMappingA),
    VFDYNF_THUNK_EX("MapViewOfFile", KernelBase_MapViewOfFile),
    VFDYNF_THUNK_EX("MapViewOfFileEx", KernelBase_MapViewOfFileEx),
    VFDYNF_THUNK_EX("UnmapViewOfFile", KernelBase_UnmapViewOfFile),
    VFDYNF_THUNK_EX("UnmapViewOfFileEx", KernelBase_UnmapViewOfFileEx),
    VFDYNF_THUNK_EX("VirtualAlloc", KernelBase_VirtualAlloc),
    VFDYNF_THUNK_EX("VirtualAllocEx", KernelBase_VirtualAllocEx),
    { NULL, 0, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpAdvapi32[] =
{
    VFDYNF_THUNK_EX("RegCreateKeyA", Advapi32_RegCreateKeyA),
    VFDYNF_THUNK_EX("RegCreateKeyW", Advapi32_RegCreateKeyW),
    VFDYNF_THUNK_EX("RegCreateKeyExA", Advapi32_RegCreateKeyExA),
    VFDYNF_THUNK_EX("RegCreateKeyExW", Advapi32_RegCreateKeyExW),
    VFDYNF_THUNK_EX("RegOpenKeyA", Advapi32_RegOpenKeyA),
    VFDYNF_THUNK_EX("RegOpenKeyW", Advapi32_RegOpenKeyW),
    VFDYNF_THUNK_EX("RegOpenKeyExA", Advapi32_RegOpenKeyExA),
    VFDYNF_THUNK_EX("RegOpenKeyExW", Advapi32_RegOpenKeyExW),
    VFDYNF_THUNK_EX("RegSetValueA", Advapi32_RegSetValueA),
    VFDYNF_THUNK_EX("RegSetValueW", Advapi32_RegSetValueW),
    VFDYNF_THUNK_EX("RegSetValueExA", Advapi32_RegSetValueExA),
    VFDYNF_THUNK_EX("RegSetValueExW", Advapi32_RegSetValueExW),
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
    { L"ntdll.dll",      0, NULL, AVrfpNtdll },
    { L"kernel32.dll",   0, NULL, AVrfpKernel32 },
    { L"kernelbase.dll", 0, NULL, AVrfpKernelBase },
    { L"advapi32.dll",   0, NULL, AVrfpAdvapi32 },
    { L"oleaut32.dll",   0, NULL, AVrfpOleAut32 },
    { NULL,              0, NULL, NULL }
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
    AVrfLinkHook(AVrfpNtdll, NtUnmapViewOfSection);
    AVrfLinkHook(AVrfpNtdll, NtUnmapViewOfSectionEx);

    AVrfLinkHook(AVrfpKernel32, Kernel32_GlobalAlloc);
    AVrfLinkHook(AVrfpKernel32, Kernel32_GlobalReAlloc);
    AVrfLinkHook(AVrfpKernel32, Kernel32_LocalAlloc);
    AVrfLinkHook(AVrfpKernel32, Kernel32_LocalReAlloc);
    AVrfLinkHook(AVrfpKernel32, Kernel32_CreateFileA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_CreateFileW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_WaitForSingleObject);
    AVrfLinkHook(AVrfpKernel32, Kernel32_WaitForSingleObjectEx);
    AVrfLinkHook(AVrfpKernel32, Kernel32_WaitForMultipleObjects);
    AVrfLinkHook(AVrfpKernel32, Kernel32_WaitForMultipleObjectsEx);
    AVrfLinkHook(AVrfpKernel32, Kernel32_CreateEventA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_CreateEventW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_OpenEventA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_OpenEventW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegCreateKeyA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegCreateKeyW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegCreateKeyExA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegCreateKeyExW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegOpenKeyA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegOpenKeyW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegOpenKeyExA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegOpenKeyExW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegSetValueA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegSetValueW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegSetValueExA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_RegSetValueExW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_CreateFileMappingW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_CreateFileMappingA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_OpenFileMappingW);
    AVrfLinkHook(AVrfpKernel32, Kernel32_OpenFileMappingA);
    AVrfLinkHook(AVrfpKernel32, Kernel32_MapViewOfFile);
    AVrfLinkHook(AVrfpKernel32, Kernel32_MapViewOfFileEx);
    AVrfLinkHook(AVrfpKernel32, Kernel32_UnmapViewOfFile);
    AVrfLinkHook(AVrfpKernel32, Kernel32_UnmapViewOfFileEx);
    AVrfLinkHook(AVrfpKernel32, Kernel32_VirtualAlloc);
    AVrfLinkHook(AVrfpKernel32, Kernel32_VirtualAllocEx);

    AVrfLinkHook(AVrfpKernelBase, KernelBase_GlobalAlloc);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_GlobalReAlloc);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_LocalAlloc);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_LocalReAlloc);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_CreateFileA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_CreateFileW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_WaitForSingleObject);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_WaitForSingleObjectEx);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_WaitForMultipleObjects);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_WaitForMultipleObjectsEx);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_CreateEventA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_CreateEventW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_OpenEventA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_OpenEventW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegCreateKeyA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegCreateKeyW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegCreateKeyExA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegCreateKeyExW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegOpenKeyA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegOpenKeyW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegOpenKeyExA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegOpenKeyExW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegSetValueA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegSetValueW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegSetValueExA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_RegSetValueExW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_CreateFileMappingW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_CreateFileMappingA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_OpenFileMappingW);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_OpenFileMappingA);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_MapViewOfFile);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_MapViewOfFileEx);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_UnmapViewOfFile);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_UnmapViewOfFileEx);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_VirtualAlloc);
    AVrfLinkHook(AVrfpKernelBase, KernelBase_VirtualAllocEx);

    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegCreateKeyA);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegCreateKeyW);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegCreateKeyExA);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegCreateKeyExW);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegOpenKeyA);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegOpenKeyW);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegOpenKeyExA);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegOpenKeyExW);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegSetValueA);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegSetValueW);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegSetValueExA);
    AVrfLinkHook(AVrfpAdvapi32, Advapi32_RegSetValueExW);

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
Hook_Kernel32_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_Kernel32_GlobalAlloc(uFlags, dwBytes);
}

HGLOBAL
WINAPI
Hook_Kernel32_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_Kernel32_GlobalReAlloc(hMem, dwBytes, uFlags);
}

HLOCAL
WINAPI
Hook_Kernel32_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_Kernel32_LocalAlloc(uFlags, uBytes);
}

HLOCAL
WINAPI
Hook_Kernel32_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_Kernel32_LocalReAlloc(hMem, uBytes, uFlags);
}

HGLOBAL
WINAPI
Hook_KernelBase_GlobalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T dwBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_KernelBase_GlobalAlloc(uFlags, dwBytes);
}

HGLOBAL
WINAPI
Hook_KernelBase_GlobalReAlloc(
    _Frees_ptr_ HGLOBAL hMem,
    _In_ SIZE_T dwBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_KernelBase_GlobalReAlloc(hMem, dwBytes, uFlags);
}

HLOCAL
WINAPI
Hook_KernelBase_LocalAlloc(
    _In_ UINT uFlags,
    _In_ SIZE_T uBytes
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_KernelBase_LocalAlloc(uFlags, uBytes);
}

HLOCAL
WINAPI
Hook_KernelBase_LocalReAlloc(
    _Frees_ptr_opt_ HLOCAL hMem,
    _In_ SIZE_T uBytes,
    _In_ UINT uFlags
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_HEAP))
    {
        return NULL;
    }

    return Orig_KernelBase_LocalReAlloc(hMem, uBytes, uFlags);
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
    NTSTATUS status;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    status = Orig_NtMapViewOfSection(SectionHandle,
                                     ProcessHandle,
                                     BaseAddress,
                                     ZeroBits,
                                     CommitSize,
                                     SectionOffset,
                                     ViewSize,
                                     InheritDisposition,
                                     AllocationType,
                                     Win32Protect);

    if (NT_SUCCESS(status) &&
        (ProcessHandle == NtCurrentProcess()) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(*BaseAddress);
    }

    return status;
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
    NTSTATUS status;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        return STATUS_NO_MEMORY;
    }

    status = Orig_NtMapViewOfSectionEx(SectionHandle,
                                       ProcessHandle,
                                       BaseAddress,
                                       SectionOffset,
                                       ViewSize,
                                       AllocationType,
                                       Win32Protect,
                                       ExtendedParameters,
                                       ExtendedParameterCount);

    if (NT_SUCCESS(status) &&
        (ProcessHandle == NtCurrentProcess()) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(*BaseAddress);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    )
{
    if ((ProcessHandle == NtCurrentProcess()) && BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS
NTAPI
Hook_NtUnmapViewOfSectionEx(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG Flags
    )
{
    if ((ProcessHandle == NtCurrentProcess()) && BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags);
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

HANDLE
NTAPI
Hook_Kernel32_CreateFileA(
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FILE))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return INVALID_HANDLE_VALUE;
    }

    return Orig_Kernel32_CreateFileA(lpFileName,
                                     dwDesiredAccess,
                                     dwShareMode,
                                     lpSecurityAttributes,
                                     dwCreationDisposition,
                                     dwFlagsAndAttributes,
                                     hTemplateFile);
}

HANDLE
NTAPI
Hook_Kernel32_CreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FILE))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return INVALID_HANDLE_VALUE;
    }

    return Orig_Kernel32_CreateFileW(lpFileName,
                                     dwDesiredAccess,
                                     dwShareMode,
                                     lpSecurityAttributes,
                                     dwCreationDisposition,
                                     dwFlagsAndAttributes,
                                     hTemplateFile);
}

HANDLE
NTAPI
Hook_KernelBase_CreateFileA(
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FILE))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return INVALID_HANDLE_VALUE;
    }

    return Orig_KernelBase_CreateFileA(lpFileName,
                                       dwDesiredAccess,
                                       dwShareMode,
                                       lpSecurityAttributes,
                                       dwCreationDisposition,
                                       dwFlagsAndAttributes,
                                       hTemplateFile);
}

HANDLE
NTAPI
Hook_KernelBase_CreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FILE))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return INVALID_HANDLE_VALUE;
    }

    return Orig_KernelBase_CreateFileW(lpFileName,
                                       dwDesiredAccess,
                                       dwShareMode,
                                       lpSecurityAttributes,
                                       dwCreationDisposition,
                                       dwFlagsAndAttributes,
                                       hTemplateFile);
}

DWORD
NTAPI
Hook_Kernel32_WaitForSingleObject(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_Kernel32_WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD
NTAPI
Hook_Kernel32_WaitForSingleObjectEx(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_Kernel32_WaitForSingleObjectEx(hHandle,
                                               dwMilliseconds,
                                               bAlertable);
}

DWORD
NTAPI
Hook_Kernel32_WaitForMultipleObjects(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_Kernel32_WaitForMultipleObjects(nCount,
                                                lpHandles,
                                                bWaitAll,
                                                dwMilliseconds);
}

DWORD
NTAPI
Hook_Kernel32_WaitForMultipleObjectsEx(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_Kernel32_WaitForMultipleObjectsEx(nCount,
                                                  lpHandles,
                                                  bWaitAll,
                                                  dwMilliseconds,
                                                  bAlertable);
}

DWORD
NTAPI
Hook_KernelBase_WaitForSingleObject(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD
NTAPI
Hook_KernelBase_WaitForSingleObjectEx(
    _In_ HANDLE hHandle,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForSingleObjectEx(hHandle,
                                                 dwMilliseconds,
                                                 bAlertable);
}

DWORD
NTAPI
Hook_KernelBase_WaitForMultipleObjects(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForMultipleObjects(nCount,
                                                  lpHandles,
                                                  bWaitAll,
                                                  dwMilliseconds);
}

DWORD
NTAPI
Hook_KernelBase_WaitForMultipleObjectsEx(
    _In_ DWORD nCount,
    _In_reads_(nCount) CONST HANDLE* lpHandles,
    _In_ BOOL bWaitAll,
    _In_ DWORD dwMilliseconds,
    _In_ BOOL bAlertable
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_WAIT))
    {
        return WAIT_TIMEOUT;
    }

    return Orig_KernelBase_WaitForMultipleObjectsEx(nCount,
                                                    lpHandles,
                                                    bWaitAll,
                                                    dwMilliseconds,
                                                    bAlertable);
}

HANDLE
WINAPI
Hook_Kernel32_CreateEventA(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_CreateEventA(lpEventAttributes,
                                      bManualReset,
                                      bInitialState,
                                      lpName);
}

HANDLE
WINAPI
Hook_Kernel32_CreateEventW(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_CreateEventW(lpEventAttributes,
                                      bManualReset,
                                      bInitialState,
                                      lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenEventA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_OpenEventA(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenEventW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_OpenEventW(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE
WINAPI
Hook_KernelBase_CreateEventA(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_CreateEventA(lpEventAttributes,
                                        bManualReset,
                                        bInitialState,
                                        lpName);
}

HANDLE
WINAPI
Hook_KernelBase_CreateEventW(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_ BOOL bManualReset,
    _In_ BOOL bInitialState,
    _In_opt_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_CreateEventW(lpEventAttributes,
                                        bManualReset,
                                        bInitialState,
                                        lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenEventA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_OpenEventA(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenEventW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_EVENT))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_OpenEventW(dwDesiredAccess, bInheritHandle, lpName);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegCreateKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegCreateKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegCreateKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegCreateKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegCreateKeyExA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegCreateKeyExA(hKey,
                                         lpSubKey,
                                         Reserved,
                                         lpClass,
                                         dwOptions,
                                         samDesired,
                                         lpSecurityAttributes,
                                         phkResult,
                                         lpdwDisposition);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegCreateKeyExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegCreateKeyExW(hKey,
                                         lpSubKey,
                                         Reserved,
                                         lpClass,
                                         dwOptions,
                                         samDesired,
                                         lpSecurityAttributes,
                                         phkResult,
                                         lpdwDisposition);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegOpenKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegOpenKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegOpenKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegOpenKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegOpenKeyExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegOpenKeyExA(hKey,
                                       lpSubKey,
                                       ulOptions,
                                       samDesired,
                                       phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegOpenKeyExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegOpenKeyExW(hKey,
                                       lpSubKey,
                                       ulOptions,
                                       samDesired,
                                       phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegSetValueA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegSetValueA(hKey,
                                      lpSubKey,
                                      dwType,
                                      lpData,
                                      cbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegSetValueW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegSetValueW(hKey,
                                      lpSubKey,
                                      dwType,
                                      lpData,
                                      cbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegSetValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegSetValueExA(hKey,
                                        lpValueName,
                                        Reserved,
                                        dwType,
                                        lpData,
                                        cbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegSetValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Kernel32_RegSetValueExW(hKey,
                                        lpValueName,
                                        Reserved,
                                        dwType,
                                        lpData,
                                        cbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegCreateKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegCreateKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegCreateKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegCreateKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegCreateKeyExA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegCreateKeyExA(hKey,
                                           lpSubKey,
                                           Reserved,
                                           lpClass,
                                           dwOptions,
                                           samDesired,
                                           lpSecurityAttributes,
                                           phkResult,
                                           lpdwDisposition);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegCreateKeyExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegCreateKeyExW(hKey,
                                           lpSubKey,
                                           Reserved,
                                           lpClass,
                                           dwOptions,
                                           samDesired,
                                           lpSecurityAttributes,
                                           phkResult,
                                           lpdwDisposition);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegOpenKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegOpenKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegOpenKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegOpenKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegOpenKeyExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegOpenKeyExA(hKey,
                                         lpSubKey,
                                         ulOptions,
                                         samDesired,
                                         phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegOpenKeyExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegOpenKeyExW(hKey,
                                         lpSubKey,
                                         ulOptions,
                                         samDesired,
                                         phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegSetValueA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegSetValueA(hKey,
                                        lpSubKey,
                                        dwType,
                                        lpData,
                                        cbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegSetValueW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegSetValueW(hKey,
                                        lpSubKey,
                                        dwType,
                                        lpData,
                                        cbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegSetValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegSetValueExA(hKey,
                                          lpValueName,
                                          Reserved,
                                          dwType,
                                          lpData,
                                          cbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegSetValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_KernelBase_RegSetValueExW(hKey,
                                          lpValueName,
                                          Reserved,
                                          dwType,
                                          lpData,
                                          cbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegCreateKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegCreateKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegCreateKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegCreateKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegCreateKeyExA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegCreateKeyExA(hKey,
                                         lpSubKey,
                                         Reserved,
                                         lpClass,
                                         dwOptions,
                                         samDesired,
                                         lpSecurityAttributes,
                                         phkResult,
                                         lpdwDisposition);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegCreateKeyExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegCreateKeyExW(hKey,
                                         lpSubKey,
                                         Reserved,
                                         lpClass,
                                         dwOptions,
                                         samDesired,
                                         lpSecurityAttributes,
                                         phkResult,
                                         lpdwDisposition);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegOpenKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegOpenKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegOpenKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegOpenKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegOpenKeyExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegOpenKeyExA(hKey,
                                       lpSubKey,
                                       ulOptions,
                                       samDesired,
                                       phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegOpenKeyExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        *phkResult = NULL;
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegOpenKeyExW(hKey,
                                       lpSubKey,
                                       ulOptions,
                                       samDesired,
                                       phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegSetValueA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegSetValueA(hKey,
                                      lpSubKey,
                                      dwType,
                                      lpData,
                                      cbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegSetValueW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegSetValueW(hKey,
                                      lpSubKey,
                                      dwType,
                                      lpData,
                                      cbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegSetValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegSetValueExA(hKey,
                                        lpValueName,
                                        Reserved,
                                        dwType,
                                        lpData,
                                        cbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegSetValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_REG))
    {
        return ERROR_OUTOFMEMORY;
    }

    return Orig_Advapi32_RegSetValueExW(hKey,
                                        lpValueName,
                                        Reserved,
                                        dwType,
                                        lpData,
                                        cbData);
}

HANDLE
WINAPI
Hook_Kernel32_CreateFileMappingW(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_CreateFileMappingW(hFile,
                                            lpFileMappingAttributes,
                                            flProtect,
                                            dwMaximumSizeHigh,
                                            dwMaximumSizeLow,
                                            lpName);
}

HANDLE
WINAPI
Hook_Kernel32_CreateFileMappingA(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_CreateFileMappingA(hFile,
                                            lpFileMappingAttributes,
                                            flProtect,
                                            dwMaximumSizeHigh,
                                            dwMaximumSizeLow,
                                            lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenFileMappingW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_OpenFileMappingW(dwDesiredAccess,
                                          bInheritHandle,
                                          lpName);
}

HANDLE
WINAPI
Hook_Kernel32_OpenFileMappingA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_OpenFileMappingA(dwDesiredAccess,
                                          bInheritHandle,
                                          lpName);
}

LPVOID
WINAPI
Hook_Kernel32_MapViewOfFile(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    )
{
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_Kernel32_MapViewOfFile(hFileMappingObject,
                                         dwDesiredAccess,
                                         dwFileOffsetHigh,
                                         dwFileOffsetLow,
                                         dwNumberOfBytesToMap);

    if (result && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
}

LPVOID
WINAPI
Hook_Kernel32_MapViewOfFileEx(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress
    )
{
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_Kernel32_MapViewOfFileEx(hFileMappingObject,
                                           dwDesiredAccess,
                                           dwFileOffsetHigh,
                                           dwFileOffsetLow,
                                           dwNumberOfBytesToMap,
                                           lpBaseAddress);

    if (result && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
}

BOOL
WINAPI
Hook_Kernel32_UnmapViewOfFile(
    _In_ PVOID BaseAddress
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_Kernel32_UnmapViewOfFile(BaseAddress);
}

BOOL
WINAPI
Hook_Kernel32_UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_Kernel32_UnmapViewOfFileEx(BaseAddress, UnmapFlags);
}

LPVOID
WINAPI
Hook_Kernel32_VirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_VirtualAlloc(lpAddress,
                                      dwSize,
                                      flAllocationType,
                                      flProtect);
}

LPVOID
WINAPI
Hook_Kernel32_VirtualAllocEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_Kernel32_VirtualAllocEx(hProcess,
                                        lpAddress,
                                        dwSize,
                                        flAllocationType,
                                        flProtect);
}

HANDLE
WINAPI
Hook_KernelBase_CreateFileMappingW(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_CreateFileMappingW(hFile,
                                              lpFileMappingAttributes,
                                              flProtect,
                                              dwMaximumSizeHigh,
                                              dwMaximumSizeLow,
                                              lpName);
}

HANDLE
WINAPI
Hook_KernelBase_CreateFileMappingA(
    _In_ HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_ DWORD flProtect,
    _In_ DWORD dwMaximumSizeHigh,
    _In_ DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_CreateFileMappingA(hFile,
                                              lpFileMappingAttributes,
                                              flProtect,
                                              dwMaximumSizeHigh,
                                              dwMaximumSizeLow,
                                              lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenFileMappingW(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCWSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_OpenFileMappingW(dwDesiredAccess,
                                            bInheritHandle,
                                            lpName);
}

HANDLE
WINAPI
Hook_KernelBase_OpenFileMappingA(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ LPCSTR lpName
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_OpenFileMappingA(dwDesiredAccess,
                                            bInheritHandle,
                                            lpName);
}

LPVOID
WINAPI
Hook_KernelBase_MapViewOfFile(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    )
{
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_KernelBase_MapViewOfFile(hFileMappingObject,
                                           dwDesiredAccess,
                                           dwFileOffsetHigh,
                                           dwFileOffsetLow,
                                           dwNumberOfBytesToMap);

    if (result && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
}

LPVOID
WINAPI
Hook_KernelBase_MapViewOfFileEx(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap,
    _In_opt_ LPVOID lpBaseAddress
    )
{
    LPVOID result;

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_SECTION))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    result = Orig_KernelBase_MapViewOfFileEx(hFileMappingObject,
                                             dwDesiredAccess,
                                             dwFileOffsetHigh,
                                             dwFileOffsetLow,
                                             dwNumberOfBytesToMap,
                                             lpBaseAddress);

    if (result && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_INPAGE))
    {
        AVrfGuardToConvertToInPageError(result);
    }

    return result;
}

BOOL
WINAPI
Hook_KernelBase_UnmapViewOfFile(
    _In_ PVOID BaseAddress
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_KernelBase_UnmapViewOfFile(BaseAddress);
}

BOOL
WINAPI
Hook_KernelBase_UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags
    )
{
    if (BaseAddress)
    {
        AVrfForgetGuardForInPageError(BaseAddress);
    }

    return Orig_KernelBase_UnmapViewOfFileEx(BaseAddress, UnmapFlags);
}

LPVOID
WINAPI
Hook_KernelBase_VirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_VirtualAlloc(lpAddress,
                                        dwSize,
                                        flAllocationType,
                                        flProtect);
}

LPVOID
WINAPI
Hook_KernelBase_VirtualAllocEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    )
{
    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_VMEM))
    {
        NtCurrentTeb()->LastErrorValue = ERROR_OUTOFMEMORY;
        return NULL;
    }

    return Orig_KernelBase_VirtualAllocEx(hProcess,
                                          lpAddress,
                                          dwSize,
                                          flAllocationType,
                                          flProtect);
}

