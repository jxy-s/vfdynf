/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#pragma once

namespace fault
{

enum class Type : uint32_t
{
    Wait,
    Heap,
    VMem,
    Reg,
    File,
    Event,
    Section,
    Ole,

    Max
};

static_assert(static_cast<uint32_t>(Type::Max) < 64, "type is used in 64bit bit field");

bool
ShouldFaultInject(
    _In_ Type FaultType,
    _In_ _Maybenull_ void* CallerAddress = VerifierGetAppCallerAddress(_ReturnAddress())
    ) noexcept;

bool
ProcessAttach(
    void
    );

void
ProcessDetach(
    void
    );

}
