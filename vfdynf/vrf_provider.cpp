#include <pch.h>

namespace provider
{

static bool g_LoadedAsVerifier = false;

RTL_VERIFIER_PROVIDER_DESCRIPTOR g_Descriptor
{
    sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR),
    thunks::g_Descriptors,
    DllLoadCallback,
    DllUnlodCallback,
    nullptr,
    0,
    0,
    nullptr,
    nullptr,
    nullptr,
    NtdllHeapFreeCallback
};

}

bool
provider::ProcessVerifier(
    _In_ HMODULE Module,
    _In_opt_ PVOID Reserved
    )
{
    auto desc = reinterpret_cast<PRTL_VERIFIER_PROVIDER_DESCRIPTOR*>(Reserved);
    if (desc == nullptr)
    {
        return false;
    }

    *desc = &g_Descriptor;

    auto err = VerifierRegisterProvider(Module, &g_Descriptor);
    if (err != ERROR_SUCCESS)
    {
        return false;
    }

    g_LoadedAsVerifier = true;
    return true;
}

bool
provider::ProcessAttach(
    _In_ HMODULE Module
    )
{
    auto err = VerifierRegisterLayerEx(Module, 
                                       &layer::g_Descriptor, 
                                       AVRF_LAYER_FLAG_TLS_SLOT);
    if (err != ERROR_SUCCESS)
    {
        return false;
    }

    //
    // Verifier will load us to get the descriptors. Verifier does this to
    // display options for users. Unless invoked with DLL_PROCESS_ATTACH we
    // must return true.
    //
    if (!g_LoadedAsVerifier)
    {
        return true;
    }

    if (layer::g_Descriptor.TlsIndex == TLS_OUT_OF_INDEXES)
    {
        DbgPrint("JXY: did not receive TLS slot from verifier");
        __debugbreak();
        return false;
    }

    layer::RecursionGuard guard;

    return fault::ProcessAttach();
}

void
provider::ProcessDetach(
    _In_ HMODULE Module
    )
{
    fault::ProcessDetach();

    VerifierUnregisterLayer(Module, &layer::g_Descriptor);
}
