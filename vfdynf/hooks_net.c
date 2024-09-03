/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <hooks.h>

int
WSAAPI
Hook_WSARecv(
    _In_ SOCKET s,
    _In_reads_(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
    _In_ DWORD dwBufferCount,
    _Out_opt_ LPDWORD lpNumberOfBytesRecvd,
    _Inout_ LPDWORD lpFlags,
    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    int res;

    if (AVrfHookIsCallerIncluded(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        for (ULONG i = 0; i < dwBufferCount; i++)
        {
            AVrfFuzzFillMemory(lpBuffers[i].buf, lpBuffers[i].len);
        }
    }

    res = Orig_WSARecv(s,
                       lpBuffers,
                       dwBufferCount,
                       lpNumberOfBytesRecvd,
                       lpFlags,
                       lpOverlapped,
                       lpCompletionRoutine);

    if ((res == 0) &&
        !lpOverlapped &&
        !lpCompletionRoutine &&
        dwBufferCount &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        for (ULONG i = 0; i < dwBufferCount; i++)
        {
            AVrfFuzzBuffer(lpBuffers[i].buf,
                           lpBuffers[i].len,
                           VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET);
        }
    }

    return res;
}

int
WSAAPI
Hook_WSARecvFrom(
    _In_ SOCKET s,
    _In_reads_(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
    _In_ DWORD dwBufferCount,
    _Out_opt_ LPDWORD lpNumberOfBytesRecvd,
    _Inout_ LPDWORD lpFlags,
    _Out_writes_bytes_to_opt_(*lpFromlen,*lpFromlen) struct sockaddr FAR * lpFrom,
    _Inout_opt_ LPINT lpFromlen,
    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    int res;

    if (AVrfHookIsCallerIncluded(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        for (ULONG i = 0; i < dwBufferCount; i++)
        {
            AVrfFuzzFillMemory(lpBuffers[i].buf, lpBuffers[i].len);
        }
    }

    res = Orig_WSARecvFrom(s,
                           lpBuffers,
                           dwBufferCount,
                           lpNumberOfBytesRecvd,
                           lpFlags,
                           lpFrom,
                           lpFromlen,
                           lpOverlapped,
                           lpCompletionRoutine);

    if ((res == 0) &&
        !lpOverlapped &&
        !lpCompletionRoutine &&
        dwBufferCount &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        for (ULONG i = 0; i < dwBufferCount; i++)
        {
            AVrfFuzzBuffer(lpBuffers[i].buf,
                           lpBuffers[i].len,
                           VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET);
        }
    }

    return res;
}

int
WSAAPI
Hook_recv(
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
    _In_ int len,
    _In_ int flags
    )
{
    int res;

    if (AVrfHookIsCallerIncluded(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        AVrfFuzzFillMemory(buf, len);
    }

    res = Orig_recv(s, buf, len, flags);

    if ((res != SOCKET_ERROR) &&
        (len > 0) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        AVrfFuzzBuffer(buf, (ULONG)len, VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET);
    }

    return res;
}

int
WSAAPI
Hook_recvfrom(
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
    _In_ int len,
    _In_ int flags,
    _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR * from,
    _Inout_opt_ int FAR * fromlen
    )
{
    int res;

    if (AVrfHookIsCallerIncluded(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        AVrfFuzzFillMemory(buf, len);
    }

    res = Orig_recvfrom(s, buf, len, flags, from, fromlen);

    if ((res != SOCKET_ERROR) &&
        (len > 0) &&
        AVrfHookShouldFaultInject(VFDYNF_FAULT_TYPE_FUZZ_NET))
    {
        AVrfFuzzBuffer(buf, (ULONG)len, VFDYNF_FAULT_TYPE_INDEX_FUZZ_NET);
    }

    return res;
}
