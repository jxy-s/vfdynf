#pragma once

BSTR 
WINAPI
Hook_SysAllocString(
    _In_opt_z_ const OLECHAR * psz
    );

INT
WINAPI
Hook_SysReAllocString(
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(_String_length_(psz)+1)) BSTR* pbstr, 
    _In_opt_z_ const OLECHAR* psz
    );

BSTR
WINAPI
Hook_SysAllocStringLen(
    _In_reads_opt_(ui) const OLECHAR * strIn, 
    UINT ui
    );

INT
WINAPI
Hook_SysReAllocStringLen(
    _Inout_ _At_(*pbstr, _Pre_z_ _Post_z_ _Post_readable_size_(len+1)) BSTR* pbstr, 
    _In_opt_z_ const OLECHAR* psz, 
    _In_ unsigned int len
    );

BSTR
WINAPI
Hook_SysAllocStringByteLen(
    _In_opt_z_ LPCSTR psz, 
    _In_ UINT len
    );
