/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <pch.h>

BOOL
WINAPI
DllMain(
    _In_ HMODULE Module,
    _In_ DWORD Reason,
    _In_ PVOID Reserved
    )
{
    switch (Reason)
    {
        case DLL_PROCESS_VERIFIER:
        {
            if (!provider::ProcessVerifier(Module, Reserved))
            {
                return FALSE;
            }
            break;
        }
        case DLL_PROCESS_ATTACH:
        {
            if (!provider::ProcessAttach(Module))
            {
                return FALSE;
            }
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            provider::ProcessDetach(Module);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        {
            break;
        }
    }

    return TRUE;
}