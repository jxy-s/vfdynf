/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

//
// We don't rely on the CRT and only rely on ntdllp.lib which gives us almost
// everything we need. But, some of the external code needs these and they
// aren't exported through ntdllp, so we implement them here for the linker.
//

_ACRTIMP _CRT_HYBRIDPATCHABLE
void __cdecl free(
    _Pre_maybenull_ _Post_invalid_ void* _Block
    )
{
    RtlFreeHeap(RtlProcessHeap(), 0, _Block);
}

_Check_return_ _Ret_maybenull_ _Post_writable_byte_size_(_Size)
_ACRTIMP _CRTALLOCATOR _CRT_JIT_INTRINSIC _CRTRESTRICT _CRT_HYBRIDPATCHABLE
void* __cdecl malloc(
    _In_ _CRT_GUARDOVERFLOW size_t _Size
    )
{
    return RtlAllocateHeap(RtlProcessHeap(), 0, _Size);
}
