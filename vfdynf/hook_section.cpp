#include <pch.h>

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
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Section))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtCreateSection,
                                thunks::g_Ntdll,
                                SectionHandle,
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
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Section))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtCreateSectionEx,
                                thunks::g_Ntdll,
                                SectionHandle,
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
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Section))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtOpenSection,
                                thunks::g_Ntdll,
                                SectionHandle,
                                DesiredAccess,
                                ObjectAttributes);
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
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Section))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtMapViewOfSection,
                                thunks::g_Ntdll,
                                SectionHandle,
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
    _Inout_updates_opt_(ParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
    )
{
    if (layer::GetRecursionCount() == 0)
    {
        layer::RecursionGuard guard;

        if (fault::ShouldFaultInject(fault::Type::Section))
        {
            return STATUS_NO_MEMORY;
        }
    }

    return thunks::CallOriginal(&Hook_NtMapViewOfSectionEx,
                                thunks::g_Ntdll,
                                SectionHandle,
                                ProcessHandle,
                                BaseAddress,
                                SectionOffset,
                                ViewSize,
                                AllocationType,
                                Win32Protect,
                                ExtendedParameters,
                                ExtendedParameterCount);
}