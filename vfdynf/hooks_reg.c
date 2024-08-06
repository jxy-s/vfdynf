/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

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

