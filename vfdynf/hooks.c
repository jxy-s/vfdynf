/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#define VFDYNF_HOOKS_PRIVATE
#include <hooks.h>

//
// N.B. Application verifier uses the thunks when patching call targets in the
// target binary and only the target binary. They effectively do IAT hooking.
// So we need to duplicate hook definitions for each possible import.
//

#define VFDYNF_THUNK(x) { #x, NULL, Hook_##x }
#define VFDYNF_THUNK_EX(m, x) { #x, NULL, Hook_##m##_##x }

#pragma warning(push)
#pragma warning(disable : 4152)

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpNtdll[] =
{
    VFDYNF_THUNK(NtOpenFile),
    VFDYNF_THUNK(NtCreateFile),
    VFDYNF_THUNK(NtReadFile),
    VFDYNF_THUNK(NtQueryInformationFile),
    VFDYNF_THUNK(NtQueryVolumeInformationFile),
    VFDYNF_THUNK(RtlAllocateHeap),
    VFDYNF_THUNK(RtlReAllocateHeap),
    VFDYNF_THUNK(NtCreateEvent),
    VFDYNF_THUNK(NtOpenEvent),
    VFDYNF_THUNK(NtCreateKey),
    VFDYNF_THUNK(NtOpenKey),
    VFDYNF_THUNK(NtSetValueKey),
    VFDYNF_THUNK(NtQueryKey),
    VFDYNF_THUNK(NtQueryValueKey),
    VFDYNF_THUNK(NtQueryMultipleValueKey),
    VFDYNF_THUNK(NtEnumerateKey),
    VFDYNF_THUNK(NtEnumerateValueKey),
    VFDYNF_THUNK(NtAllocateVirtualMemory),
    VFDYNF_THUNK(NtAllocateVirtualMemoryEx),
    VFDYNF_THUNK(NtCreateSection),
    VFDYNF_THUNK(NtOpenSection),
    VFDYNF_THUNK(NtMapViewOfSection),
    VFDYNF_THUNK(NtMapViewOfSectionEx),
    VFDYNF_THUNK(NtUnmapViewOfSection),
    VFDYNF_THUNK(NtUnmapViewOfSectionEx),
    { NULL, NULL, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpKernel32[] =
{
    VFDYNF_THUNK_EX(Kernel32, GlobalAlloc),
    VFDYNF_THUNK_EX(Kernel32, GlobalReAlloc),
    VFDYNF_THUNK_EX(Kernel32, LocalAlloc),
    VFDYNF_THUNK_EX(Kernel32, LocalReAlloc),
    VFDYNF_THUNK_EX(Kernel32, CreateFileA),
    VFDYNF_THUNK_EX(Kernel32, CreateFileW),
    VFDYNF_THUNK_EX(Kernel32, ReadFile),
    VFDYNF_THUNK_EX(Kernel32, ReadFileEx),
    VFDYNF_THUNK_EX(Kernel32, GetFileInformationByHandle),
    VFDYNF_THUNK_EX(Kernel32, GetFileSize),
    VFDYNF_THUNK_EX(Kernel32, GetFileSizeEx),
    VFDYNF_THUNK_EX(Kernel32, WaitForSingleObject),
    VFDYNF_THUNK_EX(Kernel32, WaitForSingleObjectEx),
    VFDYNF_THUNK_EX(Kernel32, WaitForMultipleObjects),
    VFDYNF_THUNK_EX(Kernel32, WaitForMultipleObjectsEx),
    VFDYNF_THUNK_EX(Kernel32, CreateEventA),
    VFDYNF_THUNK_EX(Kernel32, CreateEventW),
    VFDYNF_THUNK_EX(Kernel32, OpenEventA),
    VFDYNF_THUNK_EX(Kernel32, OpenEventW),
    VFDYNF_THUNK_EX(Kernel32, RegCreateKeyA),
    VFDYNF_THUNK_EX(Kernel32, RegCreateKeyW),
    VFDYNF_THUNK_EX(Kernel32, RegCreateKeyExA),
    VFDYNF_THUNK_EX(Kernel32, RegCreateKeyExW),
    VFDYNF_THUNK_EX(Kernel32, RegOpenKeyA),
    VFDYNF_THUNK_EX(Kernel32, RegOpenKeyW),
    VFDYNF_THUNK_EX(Kernel32, RegOpenKeyExA),
    VFDYNF_THUNK_EX(Kernel32, RegOpenKeyExW),
    VFDYNF_THUNK_EX(Kernel32, RegSetValueA),
    VFDYNF_THUNK_EX(Kernel32, RegSetValueW),
    VFDYNF_THUNK_EX(Kernel32, RegSetValueExA),
    VFDYNF_THUNK_EX(Kernel32, RegSetValueExW),
    VFDYNF_THUNK_EX(Kernel32, RegQueryValueA),
    VFDYNF_THUNK_EX(Kernel32, RegQueryValueW),
    VFDYNF_THUNK_EX(Kernel32, RegQueryMultipleValuesA),
    VFDYNF_THUNK_EX(Kernel32, RegQueryMultipleValuesW),
    VFDYNF_THUNK_EX(Kernel32, RegQueryValueExA),
    VFDYNF_THUNK_EX(Kernel32, RegQueryValueExW),
    VFDYNF_THUNK_EX(Kernel32, RegGetValueA),
    VFDYNF_THUNK_EX(Kernel32, RegGetValueW),
    VFDYNF_THUNK_EX(Kernel32, RegEnumKeyA),
    VFDYNF_THUNK_EX(Kernel32, RegEnumKeyW),
    VFDYNF_THUNK_EX(Kernel32, RegEnumKeyExA),
    VFDYNF_THUNK_EX(Kernel32, RegEnumKeyExW),
    VFDYNF_THUNK_EX(Kernel32, RegEnumValueA),
    VFDYNF_THUNK_EX(Kernel32, RegEnumValueW),
    VFDYNF_THUNK_EX(Kernel32, CreateFileMappingW),
    VFDYNF_THUNK_EX(Kernel32, CreateFileMappingA),
    VFDYNF_THUNK_EX(Kernel32, OpenFileMappingW),
    VFDYNF_THUNK_EX(Kernel32, OpenFileMappingA),
    VFDYNF_THUNK_EX(Kernel32, MapViewOfFile),
    VFDYNF_THUNK_EX(Kernel32, MapViewOfFileEx),
    VFDYNF_THUNK_EX(Kernel32, UnmapViewOfFile),
    VFDYNF_THUNK_EX(Kernel32, UnmapViewOfFileEx),
    VFDYNF_THUNK_EX(Kernel32, VirtualAlloc),
    VFDYNF_THUNK_EX(Kernel32, VirtualAllocEx),
    { NULL, NULL, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpKernelBase[] =
{
    VFDYNF_THUNK_EX(KernelBase, GlobalAlloc),
    VFDYNF_THUNK_EX(KernelBase, GlobalReAlloc),
    VFDYNF_THUNK_EX(KernelBase, LocalAlloc),
    VFDYNF_THUNK_EX(KernelBase, LocalReAlloc),
    VFDYNF_THUNK_EX(KernelBase, CreateFileA),
    VFDYNF_THUNK_EX(KernelBase, CreateFileW),
    VFDYNF_THUNK_EX(KernelBase, ReadFile),
    VFDYNF_THUNK_EX(KernelBase, ReadFileEx),
    VFDYNF_THUNK_EX(KernelBase, GetFileInformationByHandle),
    VFDYNF_THUNK_EX(KernelBase, GetFileSize),
    VFDYNF_THUNK_EX(KernelBase, GetFileSizeEx),
    VFDYNF_THUNK_EX(KernelBase, WaitForSingleObject),
    VFDYNF_THUNK_EX(KernelBase, WaitForSingleObjectEx),
    VFDYNF_THUNK_EX(KernelBase, WaitForMultipleObjects),
    VFDYNF_THUNK_EX(KernelBase, WaitForMultipleObjectsEx),
    VFDYNF_THUNK_EX(KernelBase, CreateEventA),
    VFDYNF_THUNK_EX(KernelBase, CreateEventW),
    VFDYNF_THUNK_EX(KernelBase, OpenEventA),
    VFDYNF_THUNK_EX(KernelBase, OpenEventW),
    VFDYNF_THUNK_EX(KernelBase, RegCreateKeyA),
    VFDYNF_THUNK_EX(KernelBase, RegCreateKeyW),
    VFDYNF_THUNK_EX(KernelBase, RegCreateKeyExA),
    VFDYNF_THUNK_EX(KernelBase, RegCreateKeyExW),
    VFDYNF_THUNK_EX(KernelBase, RegOpenKeyA),
    VFDYNF_THUNK_EX(KernelBase, RegOpenKeyW),
    VFDYNF_THUNK_EX(KernelBase, RegOpenKeyExA),
    VFDYNF_THUNK_EX(KernelBase, RegOpenKeyExW),
    VFDYNF_THUNK_EX(KernelBase, RegSetValueA),
    VFDYNF_THUNK_EX(KernelBase, RegSetValueW),
    VFDYNF_THUNK_EX(KernelBase, RegSetValueExA),
    VFDYNF_THUNK_EX(KernelBase, RegSetValueExW),
    VFDYNF_THUNK_EX(KernelBase, RegQueryValueA),
    VFDYNF_THUNK_EX(KernelBase, RegQueryValueW),
    VFDYNF_THUNK_EX(KernelBase, RegQueryMultipleValuesA),
    VFDYNF_THUNK_EX(KernelBase, RegQueryMultipleValuesW),
    VFDYNF_THUNK_EX(KernelBase, RegQueryValueExA),
    VFDYNF_THUNK_EX(KernelBase, RegQueryValueExW),
    VFDYNF_THUNK_EX(KernelBase, RegGetValueA),
    VFDYNF_THUNK_EX(KernelBase, RegGetValueW),
    VFDYNF_THUNK_EX(KernelBase, RegEnumKeyA),
    VFDYNF_THUNK_EX(KernelBase, RegEnumKeyW),
    VFDYNF_THUNK_EX(KernelBase, RegEnumKeyExA),
    VFDYNF_THUNK_EX(KernelBase, RegEnumKeyExW),
    VFDYNF_THUNK_EX(KernelBase, RegEnumValueA),
    VFDYNF_THUNK_EX(KernelBase, RegEnumValueW),
    VFDYNF_THUNK_EX(KernelBase, CreateFileMappingW),
    VFDYNF_THUNK_EX(KernelBase, CreateFileMappingA),
    VFDYNF_THUNK_EX(KernelBase, OpenFileMappingW),
    VFDYNF_THUNK_EX(KernelBase, OpenFileMappingA),
    VFDYNF_THUNK_EX(KernelBase, MapViewOfFile),
    VFDYNF_THUNK_EX(KernelBase, MapViewOfFileEx),
    VFDYNF_THUNK_EX(KernelBase, UnmapViewOfFile),
    VFDYNF_THUNK_EX(KernelBase, UnmapViewOfFileEx),
    VFDYNF_THUNK_EX(KernelBase, VirtualAlloc),
    VFDYNF_THUNK_EX(KernelBase, VirtualAllocEx),
    { NULL, NULL, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpAdvapi32[] =
{
    VFDYNF_THUNK_EX(Advapi32, RegCreateKeyA),
    VFDYNF_THUNK_EX(Advapi32, RegCreateKeyW),
    VFDYNF_THUNK_EX(Advapi32, RegCreateKeyExA),
    VFDYNF_THUNK_EX(Advapi32, RegCreateKeyExW),
    VFDYNF_THUNK_EX(Advapi32, RegOpenKeyA),
    VFDYNF_THUNK_EX(Advapi32, RegOpenKeyW),
    VFDYNF_THUNK_EX(Advapi32, RegOpenKeyExA),
    VFDYNF_THUNK_EX(Advapi32, RegOpenKeyExW),
    VFDYNF_THUNK_EX(Advapi32, RegSetValueA),
    VFDYNF_THUNK_EX(Advapi32, RegSetValueW),
    VFDYNF_THUNK_EX(Advapi32, RegSetValueExA),
    VFDYNF_THUNK_EX(Advapi32, RegSetValueExW),
    VFDYNF_THUNK_EX(Advapi32, RegQueryValueA),
    VFDYNF_THUNK_EX(Advapi32, RegQueryValueW),
    VFDYNF_THUNK_EX(Advapi32, RegQueryMultipleValuesA),
    VFDYNF_THUNK_EX(Advapi32, RegQueryMultipleValuesW),
    VFDYNF_THUNK_EX(Advapi32, RegQueryValueExA),
    VFDYNF_THUNK_EX(Advapi32, RegQueryValueExW),
    VFDYNF_THUNK_EX(Advapi32, RegGetValueA),
    VFDYNF_THUNK_EX(Advapi32, RegGetValueW),
    VFDYNF_THUNK_EX(Advapi32, RegEnumKeyA),
    VFDYNF_THUNK_EX(Advapi32, RegEnumKeyW),
    VFDYNF_THUNK_EX(Advapi32, RegEnumKeyExA),
    VFDYNF_THUNK_EX(Advapi32, RegEnumKeyExW),
    VFDYNF_THUNK_EX(Advapi32, RegEnumValueA),
    VFDYNF_THUNK_EX(Advapi32, RegEnumValueW),
    { NULL, NULL, NULL }
};

static RTL_VERIFIER_THUNK_DESCRIPTOR AVrfpOleAut32[] =
{
    VFDYNF_THUNK(SysAllocString),
    VFDYNF_THUNK(SysReAllocString),
    VFDYNF_THUNK(SysAllocStringLen),
    VFDYNF_THUNK(SysReAllocStringLen),
    VFDYNF_THUNK(SysAllocStringByteLen),
    { NULL, NULL, NULL }
};

#pragma warning(pop)

RTL_VERIFIER_DLL_DESCRIPTOR AVrfDllDescriptors[] =
{
    { L"ntdll.dll",      0, NULL, AVrfpNtdll },
    { L"kernelbase.dll", 0, NULL, AVrfpKernelBase },
    { L"kernel32.dll",   0, NULL, AVrfpKernel32 },
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

#define AVrfLinkHook(m, x)                                                    \
if (!AVrfpLinkHook(AVrfp##m, (PVOID)Hook_##x, (PVOID*)&Orig_##x))             \
{                                                                             \
    return FALSE;                                                             \
}

#define AVrfLinkHook2(m, x)                                                   \
if (!AVrfpLinkHook(AVrfp##m, (PVOID)Hook_##m##_##x, (PVOID*)&Orig_##m##_##x)) \
{                                                                             \
    return FALSE;                                                             \
}

BOOLEAN AVrfLinkHooks(
    VOID
    )
{
    AVrfLinkHook(Ntdll, NtOpenFile);
    AVrfLinkHook(Ntdll, NtCreateFile);
    AVrfLinkHook(Ntdll, NtReadFile);
    AVrfLinkHook(Ntdll, NtQueryInformationFile);
    AVrfLinkHook(Ntdll, NtQueryVolumeInformationFile);
    AVrfLinkHook(Ntdll, RtlAllocateHeap);
    AVrfLinkHook(Ntdll, RtlReAllocateHeap);
    AVrfLinkHook(Ntdll, NtCreateEvent);
    AVrfLinkHook(Ntdll, NtOpenEvent);
    AVrfLinkHook(Ntdll, NtCreateKey);
    AVrfLinkHook(Ntdll, NtOpenKey);
    AVrfLinkHook(Ntdll, NtSetValueKey);
    AVrfLinkHook(Ntdll, NtQueryKey);
    AVrfLinkHook(Ntdll, NtQueryValueKey);
    AVrfLinkHook(Ntdll, NtQueryMultipleValueKey);
    AVrfLinkHook(Ntdll, NtEnumerateKey);
    AVrfLinkHook(Ntdll, NtEnumerateValueKey);
    AVrfLinkHook(Ntdll, NtAllocateVirtualMemory);
    AVrfLinkHook(Ntdll, NtAllocateVirtualMemoryEx);
    AVrfLinkHook(Ntdll, NtCreateSection);
    AVrfLinkHook(Ntdll, NtOpenSection);
    AVrfLinkHook(Ntdll, NtMapViewOfSection);
    AVrfLinkHook(Ntdll, NtMapViewOfSectionEx);
    AVrfLinkHook(Ntdll, NtUnmapViewOfSection);
    AVrfLinkHook(Ntdll, NtUnmapViewOfSectionEx);

    AVrfLinkHook2(Kernel32, GlobalAlloc);
    AVrfLinkHook2(Kernel32, GlobalReAlloc);
    AVrfLinkHook2(Kernel32, LocalAlloc);
    AVrfLinkHook2(Kernel32, LocalReAlloc);
    AVrfLinkHook2(Kernel32, CreateFileA);
    AVrfLinkHook2(Kernel32, CreateFileW);
    AVrfLinkHook2(Kernel32, ReadFile);
    AVrfLinkHook2(Kernel32, ReadFileEx);
    AVrfLinkHook2(Kernel32, GetFileInformationByHandle);
    AVrfLinkHook2(Kernel32, GetFileSize);
    AVrfLinkHook2(Kernel32, GetFileSizeEx);
    AVrfLinkHook2(Kernel32, WaitForSingleObject);
    AVrfLinkHook2(Kernel32, WaitForSingleObjectEx);
    AVrfLinkHook2(Kernel32, WaitForMultipleObjects);
    AVrfLinkHook2(Kernel32, WaitForMultipleObjectsEx);
    AVrfLinkHook2(Kernel32, CreateEventA);
    AVrfLinkHook2(Kernel32, CreateEventW);
    AVrfLinkHook2(Kernel32, OpenEventA);
    AVrfLinkHook2(Kernel32, OpenEventW);
    AVrfLinkHook2(Kernel32, RegCreateKeyA);
    AVrfLinkHook2(Kernel32, RegCreateKeyW);
    AVrfLinkHook2(Kernel32, RegCreateKeyExA);
    AVrfLinkHook2(Kernel32, RegCreateKeyExW);
    AVrfLinkHook2(Kernel32, RegOpenKeyA);
    AVrfLinkHook2(Kernel32, RegOpenKeyW);
    AVrfLinkHook2(Kernel32, RegOpenKeyExA);
    AVrfLinkHook2(Kernel32, RegOpenKeyExW);
    AVrfLinkHook2(Kernel32, RegSetValueA);
    AVrfLinkHook2(Kernel32, RegSetValueW);
    AVrfLinkHook2(Kernel32, RegSetValueExA);
    AVrfLinkHook2(Kernel32, RegSetValueExW);
    AVrfLinkHook2(Kernel32, RegQueryValueA);
    AVrfLinkHook2(Kernel32, RegQueryValueW);
    AVrfLinkHook2(Kernel32, RegQueryMultipleValuesA);
    AVrfLinkHook2(Kernel32, RegQueryMultipleValuesW);
    AVrfLinkHook2(Kernel32, RegQueryValueExA);
    AVrfLinkHook2(Kernel32, RegQueryValueExW);
    AVrfLinkHook2(Kernel32, RegGetValueA);
    AVrfLinkHook2(Kernel32, RegGetValueW);
    AVrfLinkHook2(Kernel32, RegEnumKeyA);
    AVrfLinkHook2(Kernel32, RegEnumKeyW);
    AVrfLinkHook2(Kernel32, RegEnumKeyExA);
    AVrfLinkHook2(Kernel32, RegEnumKeyExW);
    AVrfLinkHook2(Kernel32, RegEnumValueA);
    AVrfLinkHook2(Kernel32, RegEnumValueW);
    AVrfLinkHook2(Kernel32, CreateFileMappingW);
    AVrfLinkHook2(Kernel32, CreateFileMappingA);
    AVrfLinkHook2(Kernel32, OpenFileMappingW);
    AVrfLinkHook2(Kernel32, OpenFileMappingA);
    AVrfLinkHook2(Kernel32, MapViewOfFile);
    AVrfLinkHook2(Kernel32, MapViewOfFileEx);
    AVrfLinkHook2(Kernel32, UnmapViewOfFile);
    AVrfLinkHook2(Kernel32, UnmapViewOfFileEx);
    AVrfLinkHook2(Kernel32, VirtualAlloc);
    AVrfLinkHook2(Kernel32, VirtualAllocEx);

    AVrfLinkHook2(KernelBase, GlobalAlloc);
    AVrfLinkHook2(KernelBase, GlobalReAlloc);
    AVrfLinkHook2(KernelBase, LocalAlloc);
    AVrfLinkHook2(KernelBase, LocalReAlloc);
    AVrfLinkHook2(KernelBase, CreateFileA);
    AVrfLinkHook2(KernelBase, CreateFileW);
    AVrfLinkHook2(KernelBase, ReadFile);
    AVrfLinkHook2(KernelBase, ReadFileEx);
    AVrfLinkHook2(KernelBase, GetFileInformationByHandle);
    AVrfLinkHook2(KernelBase, GetFileSize);
    AVrfLinkHook2(KernelBase, GetFileSizeEx);
    AVrfLinkHook2(KernelBase, WaitForSingleObject);
    AVrfLinkHook2(KernelBase, WaitForSingleObjectEx);
    AVrfLinkHook2(KernelBase, WaitForMultipleObjects);
    AVrfLinkHook2(KernelBase, WaitForMultipleObjectsEx);
    AVrfLinkHook2(KernelBase, CreateEventA);
    AVrfLinkHook2(KernelBase, CreateEventW);
    AVrfLinkHook2(KernelBase, OpenEventA);
    AVrfLinkHook2(KernelBase, OpenEventW);
    AVrfLinkHook2(KernelBase, RegCreateKeyA);
    AVrfLinkHook2(KernelBase, RegCreateKeyW);
    AVrfLinkHook2(KernelBase, RegCreateKeyExA);
    AVrfLinkHook2(KernelBase, RegCreateKeyExW);
    AVrfLinkHook2(KernelBase, RegOpenKeyA);
    AVrfLinkHook2(KernelBase, RegOpenKeyW);
    AVrfLinkHook2(KernelBase, RegOpenKeyExA);
    AVrfLinkHook2(KernelBase, RegOpenKeyExW);
    AVrfLinkHook2(KernelBase, RegSetValueA);
    AVrfLinkHook2(KernelBase, RegSetValueW);
    AVrfLinkHook2(KernelBase, RegSetValueExA);
    AVrfLinkHook2(KernelBase, RegSetValueExW);
    AVrfLinkHook2(KernelBase, RegQueryValueA);
    AVrfLinkHook2(KernelBase, RegQueryValueW);
    AVrfLinkHook2(KernelBase, RegQueryMultipleValuesA);
    AVrfLinkHook2(KernelBase, RegQueryMultipleValuesW);
    AVrfLinkHook2(KernelBase, RegQueryValueExA);
    AVrfLinkHook2(KernelBase, RegQueryValueExW);
    AVrfLinkHook2(KernelBase, RegGetValueA);
    AVrfLinkHook2(KernelBase, RegGetValueW);
    AVrfLinkHook2(KernelBase, RegEnumKeyA);
    AVrfLinkHook2(KernelBase, RegEnumKeyW);
    AVrfLinkHook2(KernelBase, RegEnumKeyExA);
    AVrfLinkHook2(KernelBase, RegEnumKeyExW);
    AVrfLinkHook2(KernelBase, RegEnumValueA);
    AVrfLinkHook2(KernelBase, RegEnumValueW);
    AVrfLinkHook2(KernelBase, CreateFileMappingW);
    AVrfLinkHook2(KernelBase, CreateFileMappingA);
    AVrfLinkHook2(KernelBase, OpenFileMappingW);
    AVrfLinkHook2(KernelBase, OpenFileMappingA);
    AVrfLinkHook2(KernelBase, MapViewOfFile);
    AVrfLinkHook2(KernelBase, MapViewOfFileEx);
    AVrfLinkHook2(KernelBase, UnmapViewOfFile);
    AVrfLinkHook2(KernelBase, UnmapViewOfFileEx);
    AVrfLinkHook2(KernelBase, VirtualAlloc);
    AVrfLinkHook2(KernelBase, VirtualAllocEx);

    AVrfLinkHook2(Advapi32, RegCreateKeyA);
    AVrfLinkHook2(Advapi32, RegCreateKeyW);
    AVrfLinkHook2(Advapi32, RegCreateKeyExA);
    AVrfLinkHook2(Advapi32, RegCreateKeyExW);
    AVrfLinkHook2(Advapi32, RegOpenKeyA);
    AVrfLinkHook2(Advapi32, RegOpenKeyW);
    AVrfLinkHook2(Advapi32, RegOpenKeyExA);
    AVrfLinkHook2(Advapi32, RegOpenKeyExW);
    AVrfLinkHook2(Advapi32, RegSetValueA);
    AVrfLinkHook2(Advapi32, RegSetValueW);
    AVrfLinkHook2(Advapi32, RegSetValueExA);
    AVrfLinkHook2(Advapi32, RegSetValueExW);
    AVrfLinkHook2(Advapi32, RegQueryValueA);
    AVrfLinkHook2(Advapi32, RegQueryValueW);
    AVrfLinkHook2(Advapi32, RegQueryMultipleValuesA);
    AVrfLinkHook2(Advapi32, RegQueryMultipleValuesW);
    AVrfLinkHook2(Advapi32, RegQueryValueExA);
    AVrfLinkHook2(Advapi32, RegQueryValueExW);
    AVrfLinkHook2(Advapi32, RegGetValueA);
    AVrfLinkHook2(Advapi32, RegGetValueW);
    AVrfLinkHook2(Advapi32, RegEnumKeyA);
    AVrfLinkHook2(Advapi32, RegEnumKeyW);
    AVrfLinkHook2(Advapi32, RegEnumKeyExA);
    AVrfLinkHook2(Advapi32, RegEnumKeyExW);
    AVrfLinkHook2(Advapi32, RegEnumValueA);
    AVrfLinkHook2(Advapi32, RegEnumValueW);

    AVrfLinkHook(OleAut32, SysAllocString);
    AVrfLinkHook(OleAut32, SysReAllocString);
    AVrfLinkHook(OleAut32, SysAllocStringLen);
    AVrfLinkHook(OleAut32, SysReAllocStringLen);
    AVrfLinkHook(OleAut32, SysAllocStringByteLen);

    return TRUE;
}
