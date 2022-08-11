/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <pch.h>

namespace layer 
{

AVRF_LAYER_DESCRIPTOR g_Descriptor
{
    &provider::g_Descriptor,
    L"{d41d391a-d897-4956-953f-ed66b3861169}",
    L"DynFault",
    1,
    0,
    nullptr,
    props::g_Descriptors,
    nullptr,
    L"Unique-stack based systematic fault injection to simulate low resource scenarios.",
    L"Dynamic Fault Injection",
    0,
    0,
    nullptr,
    props::PropertyCallback,
    props::ValidateCallback
};

static
void
SetRecursionCount(
    _In_ int32_t Value
    )
{
    assert(g_Descriptor.TlsIndex != TLS_OUT_OF_INDEXES);

    auto tls = reinterpret_cast<PVOID>(0ull + static_cast<ULONG_PTR>(Value));
    VerifierTlsSetValue(g_Descriptor.TlsIndex, tls);
}

}

int32_t
layer::GetRecursionCount(
    void
    )
{
    assert(g_Descriptor.TlsIndex != TLS_OUT_OF_INDEXES);

    auto tls = VerifierTlsGetValue(g_Descriptor.TlsIndex);
    return static_cast<uint32_t>(reinterpret_cast<ULONG_PTR>(tls));
}

layer::RecursionGuard::~RecursionGuard(
    void
    )
{
    SetRecursionCount(GetRecursionCount() - 1);
}

layer::RecursionGuard::RecursionGuard(
    void
    )
{
    SetRecursionCount(GetRecursionCount() + 1);
}
