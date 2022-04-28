#include <pch.h>

#define THUNK(x) { #x, nullptr, Hook_##x } 

namespace thunks
{

RTL_VERIFIER_THUNK_DESCRIPTOR g_Ntdll[]
{
    THUNK(NtOpenFile),
    THUNK(NtCreateFile),
    THUNK(RtlAllocateHeap),
    THUNK(RtlReAllocateHeap),
    THUNK(NtCreateEvent),
    THUNK(NtOpenEvent),
    THUNK(NtCreateKey),
    THUNK(NtOpenKey),
    THUNK(NtSetValueKey),
    THUNK(NtAllocateVirtualMemory),
    THUNK(NtAllocateVirtualMemoryEx),
    THUNK(NtCreateSection),
    THUNK(NtOpenSection),
    THUNK(NtMapViewOfSection),
    THUNK(NtMapViewOfSectionEx),
    { nullptr, 0, nullptr }
};

RTL_VERIFIER_THUNK_DESCRIPTOR g_Kernel32[]
{
    THUNK(GlobalAlloc),
    THUNK(GlobalReAlloc),
    THUNK(LocalAlloc),
    THUNK(LocalReAlloc),
    { nullptr, 0, nullptr }
};

RTL_VERIFIER_THUNK_DESCRIPTOR g_OleAut32[]
{
    THUNK(SysAllocString),
    THUNK(SysReAllocString),
    THUNK(SysAllocStringLen),
    THUNK(SysReAllocStringLen),
    THUNK(SysAllocStringByteLen),
    { nullptr, 0, nullptr }
};

RTL_VERIFIER_DLL_DESCRIPTOR g_Descriptors[]
{
    { L"ntdll.dll", 0, nullptr, g_Ntdll },
    { L"kernel32.dll", 0, nullptr, g_Kernel32 },
    { L"oleaut32.dll", 0, nullptr, g_OleAut32 },
    { nullptr, 0, nullptr, nullptr }
};

}
