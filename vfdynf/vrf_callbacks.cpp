/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

void
NTAPI
DllLoadCallback(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);
}

void
NTAPI
DllUnlodCallback(
    _In_z_ PCWSTR DllName,
    _In_ PVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_ PVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(Reserved);
}

void
NTAPI
NtdllHeapFreeCallback(
    _In_ PVOID AllocationBase,
    _In_ SIZE_T AllocationSize
    )
{
    UNREFERENCED_PARAMETER(AllocationBase);
    UNREFERENCED_PARAMETER(AllocationSize);
}
