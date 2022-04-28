/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

Properties g_Properties;

namespace props
{

AVRF_PROPERTY_DESCRIPTOR g_Descriptors[]
{
    {
        AVRF_PROPERTY_DWORD,
        L"GracePeriod",
        &g_Properties.GracePeriod,
        sizeof(g_Properties.GracePeriod),
        L"Delays fault injection until after this period, in milliseconds.",
        nullptr
    },
    {
        AVRF_PROPERTY_SZ,
        L"SymbolSearchPath",
        &g_Properties.SymbolSearchPath,
        sizeof(g_Properties.SymbolSearchPath),
        L"Symbol search path used for dynamic fault injection and applying exclusions.",
        nullptr
    },
    {
        AVRF_PROPERTY_MULTI_SZ,
        L"ExclusionsRegex",
        &g_Properties.ExclusionsRegex,
        sizeof(g_Properties.ExclusionsRegex),
        L"Excludes stack from fault injection when one of these regular expression matches the stack.",
        nullptr
    },
    {
        AVRF_PROPERTY_DWORD,
        L"DynamicFaultPeroid",
        &g_Properties.DynamicFaultPeroid,
        sizeof(g_Properties.DynamicFaultPeroid),
        L"Clears dynamic stack fault injection tracking on this period, in milliseconds, zero does not clear tracking.",
        nullptr
    },
    { AVRF_PROPERTY_NONE, nullptr, nullptr, 0, nullptr, nullptr }
};

}

DWORD
NTAPI
props::PropertyCallback(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Property
    )
{
    UNREFERENCED_PARAMETER(Property);
    return ERROR_SUCCESS;
}

DWORD
NTAPI
props::ValidateCallback(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Property
    )
{
    UNREFERENCED_PARAMETER(Property);
    return ERROR_SUCCESS;
}
