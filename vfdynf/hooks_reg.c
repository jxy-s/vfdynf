/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

VOID AVrfpCommonFuzzKeyInformation(
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Inout_updates_bytes_(ResultLength) PVOID KeyInformation,
    _In_ ULONG ResultLength
    )
{
    UNREFERENCED_PARAMETER(ResultLength);

    switch (KeyInformationClass)
    {
        case KeyBasicInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_BASIC_INFORMATION info;

                info = KeyInformation;

                AVrfFuzzBuffer(info->Name, info->NameLength);

                AVrfFuzzSizeTruncateWideString(&info->NameLength);
            }
            break;
        }
        case KeyNodeInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_NODE_INFORMATION info;

                info = KeyInformation;

                AVrfFuzzBuffer(info->Name, info->NameLength);
                AVrfFuzzBuffer(Add2Ptr(info, info->ClassOffset),
                               info->ClassLength);

                AVrfFuzzSizeTruncateWideString(&info->NameLength);
                AVrfFuzzSizeTruncateWideString(&info->ClassLength);
            }
            break;
        }
        case KeyFullInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_FULL_INFORMATION info;

                info = KeyInformation;

                AVrfFuzzBuffer(Add2Ptr(info, info->ClassOffset),
                               info->ClassLength);

                AVrfFuzzSizeTruncateWideString(&info->ClassLength);
            }
            break;
        }
        case KeyNameInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_NAME_INFORMATION info;

                info = KeyInformation;

                AVrfFuzzBuffer(info->Name, info->NameLength);

                AVrfFuzzSizeTruncateWideString(&info->NameLength);
            }
            break;
        }
        case KeyCachedInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_CACHED_INFORMATION info;

                info = KeyInformation;

                AVrfFuzzBuffer(info->Name, info->NameLength);

                AVrfFuzzSizeTruncateWideString(&info->NameLength);
            }
            break;
        }
    }
}

VOID AVrfpCommonFuzzKeyValueInformation(
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Inout_updates_bytes_(ResultLength) PVOID KeyValueInformation,
    _In_ ULONG ResultLength
    )
{
    UNREFERENCED_PARAMETER(ResultLength);

    switch (KeyValueInformationClass)
    {
        case KeyValueBasicInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_VALUE_BASIC_INFORMATION info;

                info = KeyValueInformation;

                AVrfFuzzBuffer(info->Name, info->NameLength);

                AVrfFuzzSizeTruncateWideString(&info->NameLength);
            }
            break;
        }
        case KeyValueFullInformation:
        case KeyValueFullInformationAlign64:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_VALUE_FULL_INFORMATION info;

                info = KeyValueInformation;

                AVrfFuzzBuffer(info->Name, info->NameLength);
                AVrfFuzzBuffer(Add2Ptr(info, info->DataOffset),
                               info->DataLength);

                AVrfFuzzSizeTruncateWideString(&info->DataLength);

                if ((info->Type == REG_SZ) ||
                    (info->Type == REG_EXPAND_SZ) ||
                    (info->Type == REG_MULTI_SZ))
                {
                    AVrfFuzzSizeTruncateWideString(&info->DataLength);
                }
                else
                {
                    AVrfFuzzSizeTruncateULong(&info->DataLength);
                }
            }
            break;
        }
        case KeyValuePartialInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_VALUE_PARTIAL_INFORMATION info;

                info = KeyValueInformation;

                AVrfFuzzBuffer(info->Data, info->DataLength);

                if ((info->Type == REG_SZ) ||
                    (info->Type == REG_EXPAND_SZ) ||
                    (info->Type == REG_MULTI_SZ))
                {
                    AVrfFuzzSizeTruncateWideString(&info->DataLength);
                }
                else
                {
                    AVrfFuzzSizeTruncateULong(&info->DataLength);
                }
            }
            break;
        }
        case KeyValuePartialInformationAlign64:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
            {
                PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info;

                info = KeyValueInformation;

                AVrfFuzzBuffer(info->Data, info->DataLength);

                if ((info->Type == REG_SZ) ||
                    (info->Type == REG_EXPAND_SZ) ||
                    (info->Type == REG_MULTI_SZ))
                {
                    AVrfFuzzSizeTruncateWideString(&info->DataLength);
                }
                else
                {
                    AVrfFuzzSizeTruncateULong(&info->DataLength);
                }
            }
            break;
        }
    }
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
Hook_NtQueryKey(
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    )
{
    NTSTATUS status;

    status = Orig_NtQueryKey(KeyHandle,
                             KeyInformationClass,
                             KeyInformation,
                             Length,
                             ResultLength);

    if ((status == STATUS_INFO_LENGTH_MISMATCH) ||
        (status == STATUS_BUFFER_TOO_SMALL) ||
        (status == STATUS_BUFFER_OVERFLOW))
    {
        if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *ResultLength *= 2;
        }

        return status;
    }

    if (NT_SUCCESS(status) && KeyInformation)
    {
        AVrfpCommonFuzzKeyInformation(KeyInformationClass,
                                      KeyInformation,
                                      *ResultLength);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtQueryValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    )
{
    NTSTATUS status;

    status = Orig_NtQueryValueKey(KeyHandle,
                                  ValueName,
                                  KeyValueInformationClass,
                                  KeyValueInformation,
                                  Length,
                                  ResultLength);

    if ((status == STATUS_INFO_LENGTH_MISMATCH) ||
        (status == STATUS_BUFFER_TOO_SMALL) ||
        (status == STATUS_BUFFER_OVERFLOW))
    {
        if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *ResultLength *= 2;
        }

        return status;
    }

    if (NT_SUCCESS(status) && KeyValueInformation)
    {
        AVrfpCommonFuzzKeyValueInformation(KeyValueInformationClass,
                                           KeyValueInformation,
                                           *ResultLength);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtQueryMultipleValueKey(
    _In_ HANDLE KeyHandle,
    _Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
    _In_ ULONG EntryCount,
    _Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
    _Inout_ PULONG BufferLength,
    _Out_opt_ PULONG RequiredBufferLength
    )
{
    NTSTATUS status;

    status = Orig_NtQueryMultipleValueKey(KeyHandle,
                                          ValueEntries,
                                          EntryCount,
                                          ValueBuffer,
                                          BufferLength,
                                          RequiredBufferLength);

    if ((status == STATUS_INFO_LENGTH_MISMATCH) ||
        (status == STATUS_BUFFER_TOO_SMALL) ||
        (status == STATUS_BUFFER_OVERFLOW))
    {
        if (RequiredBufferLength &&
            AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *RequiredBufferLength *= 2;
        }

        return status;
    }

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(ValueBuffer, *BufferLength);
        AVrfFuzzSizeTruncateULong(BufferLength);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtEnumerateKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    )
{
    NTSTATUS status;

    status = Orig_NtEnumerateKey(KeyHandle,
                                 Index,
                                 KeyInformationClass,
                                 KeyInformation,
                                 Length,
                                 ResultLength);

    if ((status == STATUS_INFO_LENGTH_MISMATCH) ||
        (status == STATUS_BUFFER_TOO_SMALL) ||
        (status == STATUS_BUFFER_OVERFLOW))
    {
        if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *ResultLength *= 2;
        }

        return status;
    }

    if (NT_SUCCESS(status) && KeyInformation)
    {
        AVrfpCommonFuzzKeyInformation(KeyInformationClass,
                                      KeyInformation,
                                      *ResultLength);
    }

    return status;
}

NTSTATUS
NTAPI
Hook_NtEnumerateValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    )
{
    NTSTATUS status;

    status = Orig_NtEnumerateValueKey(KeyHandle,
                                      Index,
                                      KeyValueInformationClass,
                                      KeyValueInformation,
                                      Length,
                                      ResultLength);

    if ((status == STATUS_INFO_LENGTH_MISMATCH) ||
        (status == STATUS_BUFFER_TOO_SMALL) ||
        (status == STATUS_BUFFER_OVERFLOW))
    {
        if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *ResultLength *= 2;
        }

        return status;
    }

    if (NT_SUCCESS(status) && KeyValueInformation)
    {
        AVrfpCommonFuzzKeyValueInformation(KeyValueInformationClass,
                                           KeyValueInformation,
                                           *ResultLength);
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegCreateKeyA(
    _In_ PFunc_RegCreateKeyA Orig_RegCreateKeyA,
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

    return Orig_RegCreateKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Common_RegCreateKeyW(
    _In_ PFunc_RegCreateKeyW Orig_RegCreateKeyW,
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

    return Orig_RegCreateKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Common_RegCreateKeyExA(
    _In_ PFunc_RegCreateKeyExA Orig_RegCreateKeyExA,
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

    return Orig_RegCreateKeyExA(hKey,
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
Hook_Common_RegCreateKeyExW(
    _In_ PFunc_RegCreateKeyExW Orig_RegCreateKeyExW,
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

    return Orig_RegCreateKeyExW(hKey,
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
Hook_Common_RegOpenKeyA(
    _In_ PFunc_RegOpenKeyA Orig_RegOpenKeyA,
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

    return Orig_RegOpenKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Common_RegOpenKeyW(
    _In_ PFunc_RegOpenKeyW Orig_RegOpenKeyW,
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

    return Orig_RegOpenKeyW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
Hook_Common_RegOpenKeyExA(
    _In_ PFunc_RegOpenKeyExA Orig_RegOpenKeyExA,
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

    return Orig_RegOpenKeyExA(hKey,
                              lpSubKey,
                              ulOptions,
                              samDesired,
                              phkResult);
}

LSTATUS
APIENTRY
Hook_Common_RegOpenKeyExW(
    _In_ PFunc_RegOpenKeyExW Orig_RegOpenKeyExW,
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

    return Orig_RegOpenKeyExW(hKey,
                              lpSubKey,
                              ulOptions,
                              samDesired,
                              phkResult);
}

LSTATUS
APIENTRY
Hook_Common_RegSetValueA(
    _In_ PFunc_RegSetValueA Orig_RegSetValueA,
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

    return Orig_RegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
}

LSTATUS
APIENTRY
Hook_Common_RegSetValueW(
    _In_ PFunc_RegSetValueW Orig_RegSetValueW,
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

    return Orig_RegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
}

LSTATUS
APIENTRY
Hook_Common_RegSetValueExA(
    _In_ PFunc_RegSetValueExA Orig_RegSetValueExA,
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

    return Orig_RegSetValueExA(hKey,
                               lpValueName,
                               Reserved,
                               dwType,
                               lpData,
                               cbData);
}

LSTATUS
APIENTRY
Hook_Common_RegSetValueExW(
    _In_ PFunc_RegSetValueExW Orig_RegSetValueExW,
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

    return Orig_RegSetValueExW(hKey,
                               lpValueName,
                               Reserved,
                               dwType,
                               lpData,
                               cbData);
}

LSTATUS
APIENTRY
Hook_Common_RegQueryValueA(
    _In_ PFunc_RegQueryValueA Orig_RegQueryValueA,
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    if (AVrfHookShouldVerifierStop())
    {
        VerifierStopMessageEx(&AVrfLayerDescriptor,
                              VFDYNF_CODE_DEPRECATED_FUNCTION,
                              0,
                              0,
                              0,
                              0,
                              0,
                              L"RegQueryValueA",
                              L"RegQueryValueExA");
    }

    return Orig_RegQueryValueA(hKey, lpSubKey, lpData, lpcbData);
}

LSTATUS
APIENTRY
Hook_Common_RegQueryValueW(
    _In_ PFunc_RegQueryValueW Orig_RegQueryValueW,
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    if (AVrfHookShouldVerifierStop())
    {
        VerifierStopMessageEx(&AVrfLayerDescriptor,
                              VFDYNF_CODE_DEPRECATED_FUNCTION,
                              0,
                              0,
                              0,
                              0,
                              0,
                              L"RegQueryValueW",
                              L"RegQueryValueExW");
    }

    return Orig_RegQueryValueW(hKey, lpSubKey, lpData, lpcbData);
}

LSTATUS
APIENTRY
Hook_Common_RegQueryMultipleValuesA(
    _In_ PFunc_RegQueryMultipleValuesA Orig_RegQueryMultipleValuesA,
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    LSTATUS status;

    status = Orig_RegQueryMultipleValuesA(hKey,
                                          val_list,
                                          num_vals,
                                          lpValueBuf,
                                          ldwTotsize);

    if ((status == ERROR_BAD_LENGTH) ||
        (status == ERROR_INSUFFICIENT_BUFFER) ||
        (status == ERROR_MORE_DATA))
    {
        if (ldwTotsize && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *ldwTotsize *= 2;
        }

        return status;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (lpValueBuf && ldwTotsize && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(lpValueBuf, *ldwTotsize);
        AVrfFuzzSizeTruncateULong(ldwTotsize);
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegQueryMultipleValuesW(
    _In_ PFunc_RegQueryMultipleValuesW Orig_RegQueryMultipleValuesW,
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    LSTATUS status;

    status = Orig_RegQueryMultipleValuesW(hKey,
                                          val_list,
                                          num_vals,
                                          lpValueBuf,
                                          ldwTotsize);

    if ((status == ERROR_BAD_LENGTH) ||
        (status == ERROR_INSUFFICIENT_BUFFER) ||
        (status == ERROR_MORE_DATA))
    {
        if (ldwTotsize && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *ldwTotsize *= 2;
        }

        return status;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (lpValueBuf && ldwTotsize && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(lpValueBuf, *ldwTotsize);
        AVrfFuzzSizeTruncateULong(ldwTotsize);
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegQueryValueExA(
    _In_ PFunc_RegQueryValueExA Orig_RegQueryValueExA,
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    LSTATUS status;

    status = Orig_RegQueryValueExA(hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);

    if ((status == ERROR_BAD_LENGTH) ||
        (status == ERROR_INSUFFICIENT_BUFFER) ||
        (status == ERROR_MORE_DATA))
    {
        if (lpcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *lpcbData *= 2;
        }

        return status;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (lpData && lpcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(lpData, *lpcbData);
        AVrfFuzzSizeTruncateULong(lpcbData);
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegQueryValueExW(
    _In_ PFunc_RegQueryValueExW Orig_RegQueryValueExW,
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    LSTATUS status;

    status = Orig_RegQueryValueExW(hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);

    if ((status == ERROR_BAD_LENGTH) ||
        (status == ERROR_INSUFFICIENT_BUFFER) ||
        (status == ERROR_MORE_DATA))
    {
        if (lpcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *lpcbData *= 2;
        }

        return status;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (lpData && lpcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(lpData, *lpcbData);
        AVrfFuzzSizeTruncateULong(lpcbData);
    }

    return status;
}

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_Common_RegGetValueA(
    _In_ PFunc_RegGetValueA Orig_RegGetValueA,
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
    )
{
    LSTATUS status;
    ULONG type;

    status = Orig_RegGetValueA(hkey,
                               lpSubKey,
                               lpValue,
                               dwFlags,
                               &type,
                               pvData,
                               pcbData);

    if (pdwType)
    {
        *pdwType = type;
    }

    if ((status == ERROR_BAD_LENGTH) ||
        (status == ERROR_INSUFFICIENT_BUFFER) ||
        (status == ERROR_MORE_DATA))
    {
        if (pcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *pcbData *= 2;
        }

        return status;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (pvData && pcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(pvData, *pcbData);
        AVrfFuzzSizeTruncateULong(pcbData);

        if ((*pcbData >= sizeof(CHAR)) && (type == REG_SZ) || (type == REG_EXPAND_SZ))
        {
            ((PCHAR)pvData)[*pcbData - 1] = ANSI_NULL;
        }

        if ((*pcbData >= (sizeof(CHAR) * 2)) && (type == REG_MULTI_SZ))
        {
            ((PCHAR)pvData)[*pcbData - 1] = ANSI_NULL;
            ((PCHAR)pvData)[*pcbData - 2] = ANSI_NULL;
        }
    }

    return status;
}
#pragma prefast(pop)

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_Common_RegGetValueW(
    _In_ PFunc_RegGetValueW Orig_RegGetValueW,
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
    )
{
    LSTATUS status;
    ULONG type;

    status = Orig_RegGetValueW(hkey,
                               lpSubKey,
                               lpValue,
                               dwFlags,
                               &type,
                               pvData,
                               pcbData);

    if (pdwType)
    {
        *pdwType = type;
    }

    if ((status == ERROR_BAD_LENGTH) ||
        (status == ERROR_INSUFFICIENT_BUFFER) ||
        (status == ERROR_MORE_DATA))
    {
        if (pcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
        {
            *pcbData *= 2;
        }

        return status;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (pvData && pcbData && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        AVrfFuzzBuffer(pvData, *pcbData);

        if ((type == REG_SZ) ||
            (type == REG_EXPAND_SZ) ||
            (type == REG_MULTI_SZ))
        {
            AVrfFuzzSizeTruncateWideString(pcbData);
        }
        else
        {
            AVrfFuzzSizeTruncateULong(pcbData);
        }

        if ((*pcbData >= sizeof(WCHAR)) && (type == REG_SZ) || (type == REG_EXPAND_SZ))
        {
            ((PWCHAR)pvData)[(*pcbData / sizeof(WCHAR)) - 1] = UNICODE_NULL;
        }

        if ((*pcbData >= (sizeof(WCHAR) * 2)) && (type == REG_MULTI_SZ))
        {
            ((PWCHAR)pvData)[(*pcbData / sizeof(WCHAR)) - 1] = UNICODE_NULL;
            ((PWCHAR)pvData)[(*pcbData / sizeof(WCHAR)) - 2] = UNICODE_NULL;
        }
    }

    return status;
}
#pragma prefast(pop)

LSTATUS
APIENTRY
Hook_Common_RegEnumKeyA(
    _In_ PFunc_RegEnumKeyA Orig_RegEnumKeyA,
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
    )
{
    if (AVrfHookShouldVerifierStop())
    {
        VerifierStopMessageEx(&AVrfLayerDescriptor,
                              VFDYNF_CODE_DEPRECATED_FUNCTION,
                              0,
                              0,
                              0,
                              0,
                              0,
                              L"RegEnumKeyA",
                              L"RegEnumKeyExA");
    }

    return Orig_RegEnumKeyA(hKey, dwIndex, lpName, cchName);
}

LSTATUS
APIENTRY
Hook_Common_RegEnumKeyW(
    _In_ PFunc_RegEnumKeyW Orig_RegEnumKeyW,
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
    )
{
    if (AVrfHookShouldVerifierStop())
    {
        VerifierStopMessageEx(&AVrfLayerDescriptor,
                              VFDYNF_CODE_DEPRECATED_FUNCTION,
                              0,
                              0,
                              0,
                              0,
                              0,
                              L"RegEnumKeyW",
                              L"RegEnumKeyExW");
    }

    return Orig_RegEnumKeyW(hKey, dwIndex, lpName, cchName);
}

LSTATUS
APIENTRY
Hook_Common_RegEnumKeyExA(
    _In_ PFunc_RegEnumKeyExA Orig_RegEnumKeyExA,
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    LSTATUS status;

    status = Orig_RegEnumKeyExA(hKey,
                                dwIndex,
                                lpName,
                                lpcchName,
                                lpReserved,
                                lpClass,
                                lpcchClass,
                                lpftLastWriteTime);

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (!AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        return status;
    }

    if (lpName)
    {
        AVrfFuzzBuffer(lpName, *lpcchName * sizeof(CHAR));
        AVrfFuzzSizeTruncateULong(lpcchName);
    }

    if (lpClass && lpcchClass)
    {
        AVrfFuzzBuffer(lpClass, *lpcchClass * sizeof(CHAR));
        AVrfFuzzSizeTruncateULong(lpcchClass);
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegEnumKeyExW(
    _In_ PFunc_RegEnumKeyExW Orig_RegEnumKeyExW,
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    LSTATUS status;

    status = Orig_RegEnumKeyExW(hKey,
                                dwIndex,
                                lpName,
                                lpcchName,
                                lpReserved,
                                lpClass,
                                lpcchClass,
                                lpftLastWriteTime);

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (!AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        return status;
    }

    if (lpName)
    {
        AVrfFuzzBuffer(lpName, *lpcchName * sizeof(WCHAR));
        AVrfFuzzSizeTruncateWideString(lpcchName);
    }

    if (lpClass && lpcchClass)
    {
        AVrfFuzzBuffer(lpClass, *lpcchClass * sizeof(WCHAR));
        AVrfFuzzSizeTruncateWideString(lpcchClass);
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegEnumValueA(
    _In_ PFunc_RegEnumValueA Orig_RegEnumValueA,
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    LSTATUS status;
    ULONG type;

    status = Orig_RegEnumValueA(hKey,
                                dwIndex,
                                lpValueName,
                                lpcchValueName,
                                lpReserved,
                                &type,
                                lpData,
                                lpcbData);

    if (lpType)
    {
        *lpType = type;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (!AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        return status;
    }

    if (lpValueName)
    {
        AVrfFuzzBuffer(lpValueName, *lpcchValueName * sizeof(CHAR));
        AVrfFuzzSizeTruncateULong(lpcchValueName);
    }

    if (lpData && lpcbData)
    {
        AVrfFuzzBuffer(lpData, *lpcbData);

        if ((type == REG_SZ) ||
            (type == REG_EXPAND_SZ) ||
            (type == REG_MULTI_SZ))
        {
            AVrfFuzzSizeTruncateWideString(lpcbData);
        }
        else
        {
            AVrfFuzzSizeTruncateULong(lpcbData);
        }
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Common_RegEnumValueW(
    _In_ PFunc_RegEnumValueW Orig_RegEnumValueW,
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    LSTATUS status;
    ULONG type;

    status = Orig_RegEnumValueW(hKey,
                                dwIndex,
                                lpValueName,
                                lpcchValueName,
                                lpReserved,
                                &type,
                                lpData,
                                lpcbData);

    if (lpType)
    {
        *lpType = type;
    }

    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    if (!AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_REG))
    {
        return status;
    }

    if (lpValueName)
    {
        AVrfFuzzBuffer(lpValueName, *lpcchValueName * sizeof(WCHAR));
        AVrfFuzzSizeTruncateWideString(lpcchValueName);
    }

    if (lpData && lpcbData)
    {
        AVrfFuzzBuffer(lpData, *lpcbData);

        if ((type == REG_SZ) ||
            (type == REG_EXPAND_SZ) ||
            (type == REG_MULTI_SZ))
        {
            AVrfFuzzSizeTruncateWideString(lpcbData);
        }
        else
        {
            AVrfFuzzSizeTruncateULong(lpcbData);
        }
    }

    return status;
}

LSTATUS
APIENTRY
Hook_Kernel32_RegCreateKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegCreateKeyA,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegCreateKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegCreateKeyW,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegCreateKeyExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegCreateKeyExW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegOpenKeyA,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegOpenKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegOpenKeyW,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegOpenKeyExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegOpenKeyExW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegSetValueA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegSetValueW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegSetValueExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegSetValueExW,
                                   hKey,
                                   lpValueName,
                                   Reserved,
                                   dwType,
                                   lpData,
                                   cbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegQueryValueA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegQueryValueA,
                                   hKey,
                                   lpSubKey,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegQueryValueW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegQueryValueW,
                                   hKey,
                                   lpSubKey,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegQueryMultipleValuesA(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegQueryMultipleValuesA,
                                   hKey,
                                   val_list,
                                   num_vals,
                                   lpValueBuf,
                                   ldwTotsize);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegQueryMultipleValuesW(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegQueryMultipleValuesW,
                                   hKey,
                                   val_list,
                                   num_vals,
                                   lpValueBuf,
                                   ldwTotsize);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegQueryValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegQueryValueExA,
                                   hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegQueryValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegQueryValueExW,
                                   hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_Kernel32_RegGetValueA(
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
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegGetValueA,
                                   hkey,
                                   lpSubKey,
                                   lpValue,
                                   dwFlags,
                                   pdwType,
                                   pvData,
                                   pcbData);
}
#pragma prefast(pop)

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_Kernel32_RegGetValueW(
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
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegGetValueW,
                                   hkey,
                                   lpSubKey,
                                   lpValue,
                                   dwFlags,
                                   pdwType,
                                   pvData,
                                   pcbData);
}
#pragma prefast(pop)

LSTATUS
APIENTRY
Hook_Kernel32_RegEnumKeyA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegEnumKeyA,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   cchName);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegEnumKeyW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegEnumKeyW,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   cchName);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegEnumKeyExA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegEnumKeyExA,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   lpcchName,
                                   lpReserved,
                                   lpClass,
                                   lpcchClass,
                                   lpftLastWriteTime);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegEnumKeyExW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegEnumKeyExW,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   lpcchName,
                                   lpReserved,
                                   lpClass,
                                   lpcchClass,
                                   lpftLastWriteTime);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegEnumValueA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegEnumValueA,
                                   hKey,
                                   dwIndex,
                                   lpValueName,
                                   lpcchValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Kernel32_RegEnumValueW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   RegEnumValueW,
                                   hKey,
                                   dwIndex,
                                   lpValueName,
                                   lpcchValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegCreateKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegCreateKeyA,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegCreateKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegCreateKeyW,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegCreateKeyExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegCreateKeyExW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegOpenKeyA,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegOpenKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegOpenKeyW,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegOpenKeyExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegOpenKeyExW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegSetValueA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegSetValueW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegSetValueExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegSetValueExW,
                                   hKey,
                                   lpValueName,
                                   Reserved,
                                   dwType,
                                   lpData,
                                   cbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegQueryValueA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegQueryValueA,
                                   hKey,
                                   lpSubKey,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegQueryValueW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegQueryValueW,
                                   hKey,
                                   lpSubKey,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegQueryMultipleValuesA(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegQueryMultipleValuesA,
                                   hKey,
                                   val_list,
                                   num_vals,
                                   lpValueBuf,
                                   ldwTotsize);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegQueryMultipleValuesW(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegQueryMultipleValuesW,
                                   hKey,
                                   val_list,
                                   num_vals,
                                   lpValueBuf,
                                   ldwTotsize);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegQueryValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegQueryValueExA,
                                   hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegQueryValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegQueryValueExW,
                                   hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_KernelBase_RegGetValueA(
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
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegGetValueA,
                                   hkey,
                                   lpSubKey,
                                   lpValue,
                                   dwFlags,
                                   pdwType,
                                   pvData,
                                   pcbData);
}
#pragma prefast(pop)

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_KernelBase_RegGetValueW(
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
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegGetValueW,
                                   hkey,
                                   lpSubKey,
                                   lpValue,
                                   dwFlags,
                                   pdwType,
                                   pvData,
                                   pcbData);
}
#pragma prefast(pop)

LSTATUS
APIENTRY
Hook_KernelBase_RegEnumKeyA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegEnumKeyA,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   cchName);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegEnumKeyW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegEnumKeyW,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   cchName);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegEnumKeyExA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegEnumKeyExA,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   lpcchName,
                                   lpReserved,
                                   lpClass,
                                   lpcchClass,
                                   lpftLastWriteTime);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegEnumKeyExW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegEnumKeyExW,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   lpcchName,
                                   lpReserved,
                                   lpClass,
                                   lpcchClass,
                                   lpftLastWriteTime);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegEnumValueA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegEnumValueA,
                                   hKey,
                                   dwIndex,
                                   lpValueName,
                                   lpcchValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_KernelBase_RegEnumValueW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   RegEnumValueW,
                                   hKey,
                                   dwIndex,
                                   lpValueName,
                                   lpcchValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegCreateKeyA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegCreateKeyA,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegCreateKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegCreateKeyW,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegCreateKeyExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegCreateKeyExW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegOpenKeyA,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegOpenKeyW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegOpenKeyW,
                                   hKey,
                                   lpSubKey,
                                   phkResult);
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegOpenKeyExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegOpenKeyExW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegSetValueA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegSetValueW,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegSetValueExA,
                                   hKey,
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
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegSetValueExW,
                                   hKey,
                                   lpValueName,
                                   Reserved,
                                   dwType,
                                   lpData,
                                   cbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegQueryValueA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegQueryValueA,
                                   hKey,
                                   lpSubKey,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegQueryValueW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegQueryValueW,
                                   hKey,
                                   lpSubKey,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegQueryMultipleValuesA(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegQueryMultipleValuesA,
                                   hKey,
                                   val_list,
                                   num_vals,
                                   lpValueBuf,
                                   ldwTotsize);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegQueryMultipleValuesW(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegQueryMultipleValuesW,
                                   hKey,
                                   val_list,
                                   num_vals,
                                   lpValueBuf,
                                   ldwTotsize);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegQueryValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegQueryValueExA,
                                   hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegQueryValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegQueryValueExW,
                                   hKey,
                                   lpValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_Advapi32_RegGetValueA(
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
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegGetValueA,
                                   hkey,
                                   lpSubKey,
                                   lpValue,
                                   dwFlags,
                                   pdwType,
                                   pvData,
                                   pcbData);
}
#pragma prefast(pop)

#pragma prefast(push)
#pragma prefast(disable : 6054) // String 'pvData' might not be zero-terminated.
LSTATUS
APIENTRY
Hook_Advapi32_RegGetValueW(
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
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegGetValueW,
                                   hkey,
                                   lpSubKey,
                                   lpValue,
                                   dwFlags,
                                   pdwType,
                                   pvData,
                                   pcbData);
}
#pragma prefast(pop)

LSTATUS
APIENTRY
Hook_Advapi32_RegEnumKeyA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegEnumKeyA,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   cchName);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegEnumKeyW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegEnumKeyW,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   cchName);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegEnumKeyExA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegEnumKeyExA,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   lpcchName,
                                   lpReserved,
                                   lpClass,
                                   lpcchClass,
                                   lpftLastWriteTime);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegEnumKeyExW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegEnumKeyExW,
                                   hKey,
                                   dwIndex,
                                   lpName,
                                   lpcchName,
                                   lpReserved,
                                   lpClass,
                                   lpcchClass,
                                   lpftLastWriteTime);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegEnumValueA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegEnumValueA,
                                   hKey,
                                   dwIndex,
                                   lpValueName,
                                   lpcchValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}

LSTATUS
APIENTRY
Hook_Advapi32_RegEnumValueW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Advapi32,
                                   RegEnumValueW,
                                   hKey,
                                   dwIndex,
                                   lpValueName,
                                   lpcchValueName,
                                   lpReserved,
                                   lpType,
                                   lpData,
                                   lpcbData);
}
