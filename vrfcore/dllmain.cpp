/*
    Copyright (c) Johnny Shaw. All rights reserved. 

    This project/file is necessary to generate an appropriate library for 
    vfdynf to link against. You could use lib.exe to generate a .lib file. 
    However for x86 name type undecoration is not documented for lib.exe. 
    And I haven't spent enough time to figure out how to get the compiler tool
    chain to split to an appropriate .lib from just a .def file.

    As an example with "lib.exe /DEF:vrfcore.def /MACHINE:X86 /OUT:vrfcore.lib"
    I need it to output a library with entries that look like:

  Version      : 0
  Machine      : 14C (x86)
  TimeDateStamp: 628E9CCF Wed May 25 15:17:03 2022
  SizeOfData   : 00000021
  DLL name     : vrfcore.dll
  Symbol name  : _VerifierTlsGetValue@4
  Type         : code
  Name type    : undecorate 
  Hint         : 42
  Name         : VerifierTlsGetValue

    However it generates the following:

  Version      : 0
  Machine      : 14C (x86)
  TimeDateStamp: 628E9CCF Wed May 25 15:17:03 2022
  SizeOfData   : 00000021
  DLL name     : vrfcore.dll
  Symbol name  : _VerifierTlsGetValue
  Type         : code
  Name type    : no prefix
  Hint         : 42
  Name         : VerifierTlsGetValue

    This is incorrect as the linker for vfdynf for x86 needs to find the fully
    decorated symbol but then use the undecorated in the import table. For the
    life of me I can't figure out a good way to generate using just the
    compiler tool chain. Yes, I _have_ tried specifying the decorated name
    as equal to the undecorated name in the .def file, like so:

  EXPORTS
      VerifierTlsGetValue = _VerifierTlsGetValue@4

    This also doesn't work the way I'd like it to. There are other online 
    resources that came to the same conclusion. There is also some third party
    tools to do it - but the appear to be antiquated and don't work. It's
    probably time for the community to put together a new tool that generates
    a .lib from the .dll/.def that actually works correctly.

    So, all that said, this is a "stub" vrfcore.dll just so that vfdynf can
    link against it. 
    
    *** DO NOT INSTALL THIS AS A REAPLCEMENT FOR vrfcore.dll ON YOUR SYSTEM ***

*/
#include <phnt_windows.h>
#include <phnt.h>
#include <vrfapi.h>

NTSYSAPI
NTSTATUS
NTAPI
VerifierRegisterProvider(
    _In_ HMODULE Module,
    _Inout_ PRTL_VERIFIER_PROVIDER_DESCRIPTOR Registeration
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Registeration);

    return STATUS_NO_INHERITANCE;
}


NTSYSAPI
DWORD
NTAPI
VerifierRegisterLayer(
    _In_ HMODULE Module,
    _Inout_ PAVRF_LAYER_DESCRIPTOR Layer
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Layer);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
DWORD
NTAPI
VerifierRegisterLayerEx(
    _In_ HMODULE Module,
    _Inout_ PAVRF_LAYER_DESCRIPTOR Layer,
    _In_ UCHAR Flags
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Layer);
    UNREFERENCED_PARAMETER(Flags);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
DWORD
NTAPI
VerifierUnregisterLayer(
    _In_ HMODULE Module,
    _In_ PAVRF_LAYER_DESCRIPTOR Layer
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Layer);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
PVOID
CDECL
VerifierGetAppCallerAddress(
    _In_ PVOID ReturnAddress
    )
{
    UNREFERENCED_PARAMETER(ReturnAddress);
    
    return NULL;
}

NTSYSAPI
BOOLEAN
NTAPI
VerifierShouldFaultInject(
    _In_ DWORD Class,
    _In_ PVOID CallerAddress
    )
{
    UNREFERENCED_PARAMETER(Class);
    UNREFERENCED_PARAMETER(CallerAddress);
    
    return FALSE;
}

NTSYSAPI
DWORD
NTAPI
VerifierRegisterFaultInjectProvider(
    _In_ DWORD Count,
    _Out_ PDWORD ClassBase 
    )
{
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(ClassBase);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
DWORD
NTAPI
VerifierSetFaultInjectionProbability(
    _In_ DWORD Class,
    _In_ DWORD Probability
    )
{
    UNREFERENCED_PARAMETER(Class);
    UNREFERENCED_PARAMETER(Probability);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
DWORD
NTAPI
VerifierSetAPIClassName(
    DWORD Class,
    PCWSTR Name
    )
{
    UNREFERENCED_PARAMETER(Class);
    UNREFERENCED_PARAMETER(Name);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
VOID
NTAPI
VerifierSetFaultInjectionSeed(
    DWORD Seed
    )
{
    UNREFERENCED_PARAMETER(Seed);
}

NTSYSAPI
DWORD
NTAPI
VerifierSuspendFaultInjection(
    DWORD TimeoutMs
    )
{
    UNREFERENCED_PARAMETER(TimeoutMs);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
DWORD
NTAPI
VerifierEnableFaultInjectionTargetRange(
    DWORD Class,
    PVOID StartAddress,
    PVOID EndAddress
    )
{
    UNREFERENCED_PARAMETER(Class);
    UNREFERENCED_PARAMETER(StartAddress);
    UNREFERENCED_PARAMETER(EndAddress);

    return ERROR_NOINTERFACE;
}

NTSYSAPI
DWORD
NTAPI
VerifierDisableFaultInjectionTargetRange(
    DWORD Class,
    PVOID StartAddress,
    PVOID EndAddress
    )
{
    UNREFERENCED_PARAMETER(Class);
    UNREFERENCED_PARAMETER(StartAddress);
    UNREFERENCED_PARAMETER(EndAddress);

    return ERROR_NOINTERFACE;
}

BOOL 
APIENTRY
DllMain(
    HMODULE Module,
    DWORD Reason,
    LPVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(Reserved);

    //
    // *** SEE COMMENT AT HEAD OF FILE ***
    // You should never load this DLL, if you do you're doing it wrong...
    // The _only_ purpose of this DLL is so vfdynf can link against the
    // appropriate exports from the actual vrfcore.
    // *** SEE COMMENT AT HEAD OF FILE ***
    //
    __debugbreak();

    return FALSE;
}

