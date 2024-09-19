/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#pragma once

//
// This header exposes the external PCRE2 library to the rest of the solution
// through APIs that are maintained and compiled by this the PCRE2 project
// in this solution. This is done so we can link the submodule source directly
// and compile in a compatible way for the rest of the solution. It also
// isolates the external code from the project.
//
// ext/pcre2 -> pcre2/pcre2.vcxproj -> include/pcre2_vfdynf.h
//

#ifdef __cplusplus
extern "C"
{
#endif

typedef PVOID PCRE2_HANDLE;
typedef PCRE2_HANDLE* PPCRE2_HANDLE;

VOID Pcre2Close(
    _In_ PCRE2_HANDLE Pcre2Handle
    );

_Must_inspect_result_
NTSTATUS Pcre2Compile(
    _Out_ PPCRE2_HANDLE Pcre2Handle,
    _In_ PUNICODE_STRING Pattern
    );

_Must_inspect_result_
NTSTATUS Pcre2MatchEx(
    _In_ PCRE2_HANDLE Pcre2Handle,
    _In_ PUNICODE_STRING String,
    _Out_ PBOOLEAN Match
    );

BOOLEAN Pcre2Match(
    _In_ PCRE2_HANDLE Pcre2Handle,
    _In_ PUNICODE_STRING String
    );

#ifdef __cplusplus
}
#endif
