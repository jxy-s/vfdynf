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
    {
        AVRF_PROPERTY_QWORD,
        L"EnableFaultMask",
        &g_Properties.EnableFaultMask,
        sizeof(g_Properties.EnableFaultMask),
        L"Mask of which fault types are enabled. Bit 1=Wait, 2=Heap, 3=VMem, 4=Reg, 5=File, 6=Event, 7=Section, 8=Ole.",
        nullptr
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FaultProbability",
        &g_Properties.FaultProbability,
        sizeof(g_Properties.FaultProbability),
        L"Probability that a fault will be injected (0 - 1000000).",
        nullptr
    },
    {
        AVRF_PROPERTY_DWORD,
        L"FaultSeed",
        &g_Properties.FaultSeed,
        sizeof(g_Properties.FaultSeed),
        L"Seed used for fault randomization. A value of zero will generate a random seed.",
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
