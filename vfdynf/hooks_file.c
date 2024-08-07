/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

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

NTSTATUS
NTAPI
Hook_NtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    )
{
    return Orig_NtReadFile(FileHandle,
                           Event,
                           ApcRoutine,
                           ApcContext,
                           IoStatusBlock,
                           Buffer,
                           Length,
                           ByteOffset,
                           Key);
}

NTSTATUS
NTAPI
Hook_NtQueryInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    )
{
    return Orig_NtQueryInformationFile(FileHandle,
                                       IoStatusBlock,
                                       FileInformation,
                                       Length,
                                       FileInformationClass);
}

NTSTATUS
NTAPI
Hook_NtQueryVolumeInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FSINFOCLASS FsInformationClass
    )
{
    return Orig_NtQueryVolumeInformationFile(FileHandle,
                                             IoStatusBlock,
                                             FsInformation,
                                             Length,
                                             FsInformationClass);
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

BOOL
WINAPI
Hook_Kernel32_ReadFile(
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    )
{
    return Orig_Kernel32_ReadFile(hFile,
                                  lpBuffer,
                                  nNumberOfBytesToRead,
                                  lpNumberOfBytesRead,
                                  lpOverlapped);
}

BOOL
WINAPI
Hook_Kernel32_ReadFileEx(
    _In_ HANDLE hFile,
    _Out_writes_bytes_opt_(nNumberOfBytesToRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Inout_ LPOVERLAPPED lpOverlapped,
    _In_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    return Orig_Kernel32_ReadFileEx(hFile,
                                    lpBuffer,
                                    nNumberOfBytesToRead,
                                    lpOverlapped,
                                    lpCompletionRoutine);
}

BOOL
WINAPI
Hook_Kernel32_GetFileInformationByHandle(
    _In_ HANDLE hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation
    )
{
    return Orig_Kernel32_GetFileInformationByHandle(hFile, lpFileInformation);
}

DWORD
WINAPI
Hook_Kernel32_GetFileSize(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    )
{
    return Orig_Kernel32_GetFileSize(hFile, lpFileSizeHigh);
}

BOOL
WINAPI
Hook_Kernel32_GetFileSizeEx(
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize
    )
{
    return Orig_Kernel32_GetFileSizeEx(hFile, lpFileSize);
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

BOOL
WINAPI
Hook_KernelBase_ReadFile(
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    )
{
    return Orig_KernelBase_ReadFile(hFile,
                                    lpBuffer,
                                    nNumberOfBytesToRead,
                                    lpNumberOfBytesRead,
                                    lpOverlapped);
}

BOOL
WINAPI
Hook_KernelBase_ReadFileEx(
    _In_ HANDLE hFile,
    _Out_writes_bytes_opt_(nNumberOfBytesToRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Inout_ LPOVERLAPPED lpOverlapped,
    _In_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    return Orig_KernelBase_ReadFileEx(hFile,
                                      lpBuffer,
                                      nNumberOfBytesToRead,
                                      lpOverlapped,
                                      lpCompletionRoutine);
}

BOOL
WINAPI
Hook_KernelBase_GetFileInformationByHandle(
    _In_ HANDLE hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation
    )
{
    return Orig_KernelBase_GetFileInformationByHandle(hFile, lpFileInformation);
}

DWORD
WINAPI
Hook_KernelBase_GetFileSize(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    )
{
    return Orig_KernelBase_GetFileSize(hFile, lpFileSizeHigh);
}

BOOL
WINAPI
Hook_KernelBase_GetFileSizeEx(
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize
    )
{
    return Orig_KernelBase_GetFileSizeEx(hFile, lpFileSize);
}

