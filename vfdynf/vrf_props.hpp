#pragma once

struct Properties
{
    uint32_t GracePeriod = 2000;
    wchar_t SymbolSearchPath[1024]{};
    wchar_t ExclusionsRegex[1024 * 1024]{};
    uint32_t DynamicFaultPeroid = 30000;
};

extern Properties g_Properties;

namespace props
{

extern AVRF_PROPERTY_DESCRIPTOR g_Descriptors[];

DWORD
NTAPI
PropertyCallback(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Property
    );

DWORD
NTAPI
ValidateCallback(
    _In_ PAVRF_PROPERTY_DESCRIPTOR Property
    );

}
