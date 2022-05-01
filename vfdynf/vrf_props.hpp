/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#pragma once

struct Properties
{
    uint32_t GracePeriod = 5000;
    wchar_t SymbolSearchPath[1024]{ L'\0' };
    wchar_t ExclusionsRegex[64 * 1024]{ L'\0' };
    uint32_t DynamicFaultPeroid = 30000;
    uint64_t EnableFaultMask = (fault::FaultTypeToBit(fault::Type::Wait) |
                                fault::FaultTypeToBit(fault::Type::Event) |
                                fault::FaultTypeToBit(fault::Type::Heap) |
                                fault::FaultTypeToBit(fault::Type::VMem) |
                                fault::FaultTypeToBit(fault::Type::Reg) |
                                fault::FaultTypeToBit(fault::Type::File) |
                                fault::FaultTypeToBit(fault::Type::Event) |
                                fault::FaultTypeToBit(fault::Type::Section) |
                                fault::FaultTypeToBit(fault::Type::Ole));
    uint32_t FaultProbability = 1000000;
    uint32_t FaultSeed = 0;
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
