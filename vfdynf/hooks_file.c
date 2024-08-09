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
    NTSTATUS status;

    status = Orig_NtReadFile(FileHandle,
                             Event,
                             ApcRoutine,
                             ApcContext,
                             IoStatusBlock,
                             Buffer,
                             Length,
                             ByteOffset,
                             Key);

    if (!NT_SUCCESS(status) || (status == STATUS_PENDING))
    {
        return status;
    }

    if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
    {
        LARGE_INTEGER bytesRead;

        AVrfFuzzBuffer(Buffer, IoStatusBlock->Information);

        bytesRead.QuadPart = IoStatusBlock->Information;

        AVrfFuzzSizeTruncate(&bytesRead);

        IoStatusBlock->Information = (ULONG_PTR)bytesRead.QuadPart;
    }

    return status;
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
    NTSTATUS status;

    status = Orig_NtQueryInformationFile(FileHandle,
                                         IoStatusBlock,
                                         FileInformation,
                                         Length,
                                         FileInformationClass);

    if ((status == STATUS_INFO_LENGTH_MISMATCH) ||
        (status == STATUS_BUFFER_TOO_SMALL) ||
        (status == STATUS_BUFFER_OVERFLOW))
    {
        if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
        {
            IoStatusBlock->Information *= 2;
        }

        return status;
    }

    if (!NT_SUCCESS(status) || (status == STATUS_PENDING))
    {
        return status;
    }

    switch (FileInformationClass)
    {
        case FileStandardInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
            {
                PFILE_STANDARD_INFORMATION info;
                LARGE_INTEGER size;

                info = FileInformation;

                AVrfFuzzSize(&size);

                info->EndOfFile = size;
                size.QuadPart = ((size.QuadPart + 0xffff) & ~0xffff);
                info->AllocationSize = size;
            }
            break;
        }
        case FileAllInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
            {
                PFILE_ALL_INFORMATION info;
                LARGE_INTEGER size;

                info = FileInformation;

                AVrfFuzzSize(&size);

                info->StandardInformation.EndOfFile = size;
                size.QuadPart = ((size.QuadPart + 0xffff) & ~0xffff);
                info->StandardInformation.AllocationSize = size;
            }
            break;
        }
        case FileAllocationInformation:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
            {
                PFILE_ALLOCATION_INFORMATION info;
                LARGE_INTEGER size;

                info = FileInformation;

                AVrfFuzzSize(&size);

                size.QuadPart = ((size.QuadPart + 0xffff) & ~0xffff);
                info->AllocationSize = size;
            }
            break;
        }
        case FileEndOfFileInfo:
        {
            if (AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
            {
                PFILE_END_OF_FILE_INFORMATION info;

                info = FileInformation;

                AVrfFuzzSize(&info->EndOfFile);
            }
            break;
        }
        default:
        {
            break;
        }
    }

    return status;
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
Hook_Common_CreateFileA(
    _In_ PFunc_CreateFileA Orig_CreateFileA,
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

    return Orig_CreateFileA(lpFileName,
                            dwDesiredAccess,
                            dwShareMode,
                            lpSecurityAttributes,
                            dwCreationDisposition,
                            dwFlagsAndAttributes,
                            hTemplateFile);
}

HANDLE
NTAPI
Hook_Common_CreateFileW(
    _In_ PFunc_CreateFileW Orig_CreateFileW,
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

    return Orig_CreateFileW(lpFileName,
                            dwDesiredAccess,
                            dwShareMode,
                            lpSecurityAttributes,
                            dwCreationDisposition,
                            dwFlagsAndAttributes,
                            hTemplateFile);
}

BOOL
WINAPI
Hook_Common_ReadFile(
    _In_ PFunc_ReadFile Orig_ReadFile,
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    )
{
    BOOL result;

    result = Orig_ReadFile(hFile,
                           lpBuffer,
                           nNumberOfBytesToRead,
                           lpNumberOfBytesRead,
                           lpOverlapped);

    if (result && lpBuffer && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
    {
        AVrfFuzzBuffer(lpBuffer, nNumberOfBytesToRead);

        if (lpNumberOfBytesRead)
        {
            AVrfFuzzSizeTruncateULong(lpNumberOfBytesRead);
        }
    }

    return result;
}

BOOL
WINAPI
Hook_Common_ReadFileEx(
    _In_ PFunc_ReadFileEx Orig_ReadFileEx,
    _In_ HANDLE hFile,
    _Out_writes_bytes_opt_(nNumberOfBytesToRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Inout_ LPOVERLAPPED lpOverlapped,
    _In_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    return Orig_ReadFileEx(hFile,
                           lpBuffer,
                           nNumberOfBytesToRead,
                           lpOverlapped,
                           lpCompletionRoutine);
}

BOOL
WINAPI
Hook_Common_GetFileInformationByHandle(
    _In_ PFunc_GetFileInformationByHandle Orig_GetFileInformationByHandle,
    _In_ HANDLE hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation
    )
{
    BOOL result;

    result = Orig_GetFileInformationByHandle(hFile, lpFileInformation);

    if (result && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
    {
        LARGE_INTEGER fileSize;

        fileSize.HighPart = lpFileInformation->nFileSizeHigh;
        fileSize.LowPart = lpFileInformation->nFileIndexLow;

        AVrfFuzzSize(&fileSize);

        lpFileInformation->nFileSizeHigh = fileSize.HighPart;
        lpFileInformation->nFileIndexLow = fileSize.LowPart;
    }

    return result;
}

DWORD
WINAPI
Hook_Common_GetFileSize(
    _In_ PFunc_GetFileSize Orig_GetFileSize,
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    )
{
    VerifierStopMessageEx(&AVrfLayerDescriptor,
                          VFDYNF_CODE_DEPRECATED_FUNCTION,
                          0,
                          0,
                          0,
                          0,
                          0,
                          L"GetFileSize",
                          L"GetFileSizeEx");

    return Orig_GetFileSize(hFile, lpFileSizeHigh);
}

BOOL
WINAPI
Hook_Common_GetFileSizeEx(
    _In_ PFunc_GetFileSizeEx Orig_GetFileSizeEx,
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize
    )
{
    BOOL result;

    result = Orig_GetFileSizeEx(hFile, lpFileSize);

    if (result && AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_FILE))
    {
        AVrfFuzzSize(lpFileSize);
    }

    return result;
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   CreateFileA,
                                   lpFileName,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   CreateFileW,
                                   lpFileName,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   ReadFile,
                                   hFile,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   ReadFileEx,
                                   hFile,
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
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   GetFileInformationByHandle,
                                   hFile,
                                   lpFileInformation);
}

DWORD
WINAPI
Hook_Kernel32_GetFileSize(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   GetFileSize,
                                   hFile,
                                   lpFileSizeHigh);
}

BOOL
WINAPI
Hook_Kernel32_GetFileSizeEx(
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(Kernel32,
                                   GetFileSizeEx,
                                   hFile,
                                   lpFileSize);
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   CreateFileA,
                                   lpFileName,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   CreateFileW,
                                   lpFileName,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   ReadFile,
                                   hFile,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   ReadFileEx,
                                   hFile,
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
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   GetFileInformationByHandle,
                                   hFile,
                                   lpFileInformation);
}

DWORD
WINAPI
Hook_KernelBase_GetFileSize(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   GetFileSize,
                                   hFile,
                                   lpFileSizeHigh);
}

BOOL
WINAPI
Hook_KernelBase_GetFileSizeEx(
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize
    )
{
    return VFDYNF_LINK_COMMON_HOOK(KernelBase,
                                   GetFileSizeEx,
                                   hFile,
                                   lpFileSize);
}

