/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#pragma once

namespace thunks
{

extern RTL_VERIFIER_THUNK_DESCRIPTOR g_Ntdll[];

extern RTL_VERIFIER_THUNK_DESCRIPTOR g_Kernel32[];

extern RTL_VERIFIER_THUNK_DESCRIPTOR g_OleAut32[];

extern RTL_VERIFIER_DLL_DESCRIPTOR g_Descriptors[];

template <typename TFunc, typename... TArgs>
std::invoke_result_t<TFunc, TArgs...>
CallOriginal(
    TFunc* Hook,
    const RTL_VERIFIER_THUNK_DESCRIPTOR* Thunks,
    TArgs&&... Args
    )
{
    TFunc* target = nullptr;
    for (size_t i = 0;
         Thunks[i].ThunkNewAddress != nullptr;
         i++)
    {
        if (Thunks[i].ThunkNewAddress == Hook)
        {
            target = reinterpret_cast<TFunc*>(Thunks[i].ThunkOldAddress);
            break;
        }
    }

    if (target == nullptr)
    {
        DbgPrint("AVRF: there is no replacement for the hook!");
        __debugbreak();
        std::abort();
    }

    return target(std::forward<TArgs>(Args)...);
}

}
