/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#pragma once

_Must_inspect_result_
BOOLEAN AVrfDelayLoadInitOnce(
    VOID
    );

_Must_inspect_result_
BOOLEAN AVrfInDelayLoadDll(
    _In_opt_ _Maybenull_ PVOID Address
    );

#ifdef VFDYNF_DELAYLD_PRIVATE
#define VFDYNF_ORIG_QUAL
#define VFDYNF_ORIG_INIT = NULL
#else
#define VFDYNF_ORIG_QUAL extern
#define VFDYNF_ORIG_INIT
#endif

#define VFDYNF_DECLARE_DELAYLD_TYPEDEF(ret, conv, name, params)               \
    typedef ret conv DelayFunc_##name params;                                 \
    typedef DelayFunc_##name* PDelayFunc_##name;

#define VFDYNF_DECLARE_DELAYLD(ret, conv, name, params)                       \
    VFDYNF_DECLARE_DELAYLD_TYPEDEF(ret, conv, name, params)                   \
    VFDYNF_ORIG_QUAL PDelayFunc_##name Delay_##name VFDYNF_ORIG_INIT

VFDYNF_DECLARE_DELAYLD(
NTSTATUS,
WINAPI,
BCryptGenRandom, (
    _In_opt_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Out_writes_bytes_(cbBuffer)PUCHAR  pbBuffer,
    _In_ ULONG cbBuffer,
    _In_ ULONG dwFlags
    ));

VFDYNF_DECLARE_DELAYLD(
BOOL,
IMAGEAPI,
SymCleanup, (
    _In_ HANDLE hProcess
    ));

VFDYNF_DECLARE_DELAYLD(
DWORD,
IMAGEAPI,
SymSetOptions, (
    _In_ DWORD   SymOptions
    ));

VFDYNF_DECLARE_DELAYLD(
DWORD,
IMAGEAPI,
SymGetOptions, (
    VOID
    ));

VFDYNF_DECLARE_DELAYLD(
BOOL,
IMAGEAPI,
SymInitializeW, (
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess
    ));

VFDYNF_DECLARE_DELAYLD(
BOOL,
IMAGEAPI,
SymRefreshModuleList, (
    _In_ HANDLE hProcess
    ));

VFDYNF_DECLARE_DELAYLD(
BOOL,
IMAGEAPI,
SymFromAddrW, (
    _In_ HANDLE hProcess,
    _In_ DWORD64 Address,
    _Out_opt_ PDWORD64 Displacement,
    _Inout_ PSYMBOL_INFOW Symbol
    ));

VFDYNF_DECLARE_DELAYLD(
BOOL,
IMAGEAPI,
SymRegisterCallbackW64, (
    _In_ HANDLE hProcess,
    _In_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext
    ));

VFDYNF_DECLARE_DELAYLD(
DWORD64,
IMAGEAPI,
SymLoadModuleExW, (
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_opt_ DWORD Flags
    ));

VFDYNF_DECLARE_DELAYLD(
BOOL,
IMAGEAPI,
SymUnloadModule64, (
    _In_ HANDLE hProcess,
    _In_ DWORD64 BaseOfDll
    ));
