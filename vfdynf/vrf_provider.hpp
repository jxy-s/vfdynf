/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#pragma once

namespace provider
{

extern RTL_VERIFIER_PROVIDER_DESCRIPTOR g_Descriptor;

bool
ProcessVerifier(
    _In_ HMODULE Module,
    _In_opt_ PVOID Reserved
    );

bool
ProcessAttach(
    _In_ HMODULE Module
    );

void
ProcessDetach(
    _In_ HMODULE Module
    );

}
