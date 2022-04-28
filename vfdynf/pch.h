#pragma once

#include <phnt_windows.h>
#include <phnt.h>

#include <intrin.h>
#include <vrfapi.h>
#include <DbgHelp.h>
#include <oleauto.h>
#include <assert.h>

#include <type_traits>
#include <string>
#include <regex>
#include <mutex>
#include <unordered_map>

#include <vrf_provider.hpp>
#include <vrf_fault.hpp>
#include <vrf_thunks.hpp>
#include <vrf_props.hpp>
#include <vrf_callbacks.hpp>
#include <vrf_layer.hpp>

#include <hook_file.hpp>
#include <hook_heap.hpp>
#include <hook_ole.hpp>
#include <hook_event.hpp>
#include <hook_wait.hpp>
#include <hook_reg.hpp>
#include <hook_vmem.hpp>
#include <hook_section.hpp>

#ifndef Add2Ptr
#define Add2Ptr(P, I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#ifndef PtrOffset
#define PtrOffset(B, O) ((ULONG)((ULONG_PTR)(O) - (ULONG_PTR)(B)))
#endif
