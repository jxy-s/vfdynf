/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <delayld.h>

#define VFDYNF_FUZZ_BLOCK_SIZE  (0x1000 / 4)
#define VFDYNF_RAND_VECTOR_SIZE 0x4000
#define VFDYNF_FUZZ_MMAP_COUNT  1024

typedef struct _VFDYNF_FUZZ_MMAP_ENTRY
{
    PVOID OriginalBaseAddress;
    PVOID FuzzedBaseAddress;
} VFDYNF_FUZZ_MMAP_ENTRY, *PVFDYNF_FUZZ_MMAP_ENTRY;

typedef struct _VFDYNF_FUZZ_CONTEXT
{
    BOOLEAN Initialized;
    volatile LONG Index;
    BYTE Vector[0x4000];
    RTL_CRITICAL_SECTION CriticalSection;
    ULONG MMapEntryCount;
    VFDYNF_FUZZ_MMAP_ENTRY MMapEntries[VFDYNF_FUZZ_MMAP_COUNT];
} VFDYNF_FUZZ_CONTEXT, *PVFDYNF_FUZZ_CONTEXT;

static AVRF_RUN_ONCE AVrfpFuzzRunOnce = AVRF_RUN_ONCE_INIT;

static VFDYNF_FUZZ_CONTEXT AVrfpFuzzContext =
{
    .Initialized = FALSE,
    .Index = 0,
    .Vector = { 0 },
    .CriticalSection = { 0 },
    .MMapEntryCount = 0,
    .MMapEntries = { 0 },
};

_Function_class_(AVRF_RUN_ONCE_ROUTINE)
BOOLEAN NTAPI AVrfpFuzzRunOnceRoutine(
    VOID
    )
{
    NTSTATUS status;

    AVrfDisableCurrentThreadFaultInjection();

    status = Delay_BCryptGenRandom(NULL,
                                   AVrfpFuzzContext.Vector,
                                   VFDYNF_RAND_VECTOR_SIZE,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    AVrfEnableCurrentThreadFaultInjection();

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: failed to initialize fuzz vector (0x%08x)\n",
                   status);
        __debugbreak();
        return FALSE;
    }

    return TRUE;
}

ULONG AVrfFuzzRandom(
    VOID
    )
{
    ULONG index;

    if (!AVrfDelayLoadInitOnce() ||
        !AVrfRunOnce(&AVrfpFuzzRunOnce, AVrfpFuzzRunOnceRoutine, FALSE))
    {
        return (ULONG)ReadTimeStampCounter();
    }

    index = (ULONG)InterlockedIncrement(&AVrfpFuzzContext.Index);

    return *(PULONG)&AVrfpFuzzContext.Vector[index % VFDYNF_RAND_VECTOR_SIZE];
}

BOOLEAN AVrfFuzzProbability(
    _In_ ULONG Probability
    )
{
    if (!Probability)
    {
        return FALSE;
    }

    if (Probability >= 1000000)
    {
        return TRUE;
    }

    return ((AVrfFuzzRandom() % 1000000) < Probability);
}

VOID AVrfpFuzzBuffer(
    _Inout_bytecount_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    )
{
    PBYTE bufferBytes;
    SIZE_T bufferLength;
    ULONG corruptionBlocks;

    if (!AVrfProperties.FuzzCorruptionBlocks)
    {
        return;
    }

    bufferBytes = Buffer;
    bufferLength = Length;
    corruptionBlocks = (1 + (AVrfFuzzRandom() % AVrfProperties.FuzzCorruptionBlocks));

    for (ULONG i = 0; i < corruptionBlocks; i++)
    {
        if (AVrfFuzzProbability(AVrfProperties.FuzzChaosProbability))
        {
            ULONG offsets[2];
            ULONG start;
            ULONG end;

            offsets[0] = AVrfFuzzRandom() % bufferLength;
            offsets[1] = AVrfFuzzRandom() % bufferLength;

            start = offsets[0] < offsets[1] ? offsets[0] : offsets[1];
            end = offsets[0] > offsets[1] ? offsets[0] : offsets[1];

            while (start < end)
            {
                bufferBytes[start++] = (BYTE)AVrfFuzzRandom();
            }
        }
        else
        {
            ULONG position;

            position = AVrfFuzzRandom() % bufferLength;

            if (AVrfFuzzProbability(250000))
            {
                position &= 0xfffffffc;
            }

            if ((position + 3) >= bufferLength)
            {
                bufferBytes[position] ^= (BYTE)(1 + AVrfFuzzRandom());
                continue;
            }

            switch (AVrfFuzzRandom() % 13)
            {
                case 1: // off by a bit
                {
                    *(PULONG)&bufferBytes[position] += 512 - (ULONG)(AVrfFuzzRandom() % 1024);
                    break;
                }
                case 2: // off by multiple of four
                {
                    *(PULONG)&bufferBytes[position] += 4 * (512 - (ULONG)(AVrfFuzzRandom() % 1024));
                    break;
                }
                case 3: // negative one
                {
                    *(PULONG)&bufferBytes[position] = 0xffffffff;
                    break;
                }
                case 4: // small negative
                {
                    *(PULONG)&bufferBytes[position] = -(LONG)(AVrfFuzzRandom() % 25);
                    break;
                }
                case 5: // zero
                {
                    *(PULONG)&bufferBytes[position] = 0;
                    break;
                }
                case 6: // negate
                {
                    *(PULONG)&bufferBytes[position] = -(*(PLONG)&bufferBytes[position]);
                    break;
                }
                case 7: // compliment
                {
                    *(PULONG)&bufferBytes[position] = ~(*(PLONG)&bufferBytes[position]);
                    break;
                }
                case 8: // treat position as offset
                {
                    *(PULONG)&bufferBytes[position] = (ULONG)position + 4 * (128 - (ULONG)(AVrfFuzzRandom() % 256));
                    break;
                }
                case 9: // copy alternate dword
                {
                    *(PULONG)&bufferBytes[position] = *(PULONG)&bufferBytes[AVrfFuzzRandom() % (bufferLength - 3)];
                    break;
                }
                default: // random dword
                {
                    *(PULONG)&bufferBytes[position] = (ULONG)(1 + AVrfFuzzRandom());
                    break;
                }
            }
        }
    }
}

VOID AVrfFuzzBuffer(
    _Inout_bytecount_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    )
{
    SIZE_T remaining;

    remaining = Length;

    while (remaining)
    {
        PVOID buffer;
        SIZE_T blockLength;

        buffer = Add2Ptr(Buffer, Length - remaining);
        blockLength = min(remaining, VFDYNF_FUZZ_BLOCK_SIZE);

        AVrfpFuzzBuffer(buffer, blockLength);

        remaining -= blockLength;
    }
}

VOID AVrfFuzzSize(
    _Out_ PLARGE_INTEGER Size
    )
{
    switch (AVrfFuzzRandom() % 5)
    {
        case 1: // small value
        {
            Size->HighPart = 0;
            Size->LowPart = AVrfFuzzRandom() % 32;
            break;
        }
        case 2: // huge value
        {
            Size->HighPart = AVrfFuzzRandom();
            Size->LowPart = AVrfFuzzRandom();

            if (Size->HighPart < 0)
            {
                Size->HighPart = -Size->HighPart;
            }

            break;
        }
        default:
        {
            Size->HighPart = 0;
            Size->LowPart = AVrfFuzzRandom();
            break;
        }
    }
}

VOID AVrfFuzzSizeTruncate(
    _Inout_ PLARGE_INTEGER Size
    )
{
    if (Size->QuadPart <= 0)
    {
        return;
    }

    if (AVrfFuzzProbability(AVrfProperties.FuzzSizeTruncateProbability))
    {
        LARGE_INTEGER size;

        AVrfFuzzSize(&size);

        Size->QuadPart = (size.QuadPart % Size->QuadPart);
    }
}

VOID AVrfFuzzSizeTruncateULong(
    _Inout_ PULONG Size
    )
{
    LARGE_INTEGER size;

    size.QuadPart = *Size;

    AVrfFuzzSizeTruncate(&size);

    *Size = size.LowPart;
}

VOID AVrfFuzzSizeTruncateWideString(
    _Inout_ PULONG Size
    )
{
    LARGE_INTEGER size;

    size.QuadPart = *Size;

    AVrfFuzzSizeTruncate(&size);

    if (size.LowPart % 2)
    {
        size.LowPart--;
    }

    *Size = size.LowPart;
}

PVOID AVrfFuzzMemoryMapping(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize
    )
{
    NTSTATUS status;
    PVOID baseAddress;
    PVFDYNF_FUZZ_MMAP_ENTRY entry;

    if (!RegionSize)
    {
        return BaseAddress;
    }

    baseAddress = RtlAllocateHeap(RtlProcessHeap(), 0, RegionSize);
    if (!baseAddress)
    {
        return BaseAddress;
    }

    status = RtlEnterCriticalSection(&AVrfpFuzzContext.CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));

    if (AVrfpFuzzContext.MMapEntryCount < VFDYNF_FUZZ_MMAP_COUNT)
    {
        entry = &AVrfpFuzzContext.MMapEntries[AVrfpFuzzContext.MMapEntryCount++];

        entry->OriginalBaseAddress = BaseAddress;
        entry->FuzzedBaseAddress = baseAddress;

        __try
        {
            RtlCopyMemory(baseAddress, BaseAddress, RegionSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        AVrfFuzzBuffer(baseAddress, RegionSize);
    }
    else
    {
        DbgPrintEx(DPFLTR_VERIFIER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "AVRF: out of fuzzing mmap slots!");
        __debugbreak();

        RtlFreeHeap(RtlProcessHeap(), 0, baseAddress);

        baseAddress = BaseAddress;
    }

    RtlLeaveCriticalSection(&AVrfpFuzzContext.CriticalSection);

    return baseAddress;
}

PVOID AVrfForgetFuzzedMemoryMapping(
    _In_ PVOID BaseAddress
    )
{
    NTSTATUS status;
    PVOID baseAddress;

    baseAddress = BaseAddress;

    status = RtlEnterCriticalSection(&AVrfpFuzzContext.CriticalSection);

    AVRF_ASSERT(NT_SUCCESS(status));

    for (ULONG i = 0; i < AVrfpFuzzContext.MMapEntryCount; i++)
    {
        PVFDYNF_FUZZ_MMAP_ENTRY entry;
        ULONG length;

        entry = &AVrfpFuzzContext.MMapEntries[i];

        if (entry->FuzzedBaseAddress != BaseAddress)
        {
            continue;
        }

        RtlFreeHeap(RtlProcessHeap(), 0, BaseAddress);

        baseAddress = entry->OriginalBaseAddress;

        AVrfpFuzzContext.MMapEntryCount--;

        length = ((AVrfpFuzzContext.MMapEntryCount - i) * sizeof(*entry));

        RtlMoveMemory(entry, entry + 1, length);

        break;
    }

    RtlLeaveCriticalSection(&AVrfpFuzzContext.CriticalSection);

    return baseAddress;
}

BOOLEAN AVrfFuzzProcessAttach(
    VOID
    )
{
    NTSTATUS status;

    status = RtlInitializeCriticalSection(&AVrfpFuzzContext.CriticalSection);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    AVrfpFuzzContext.Initialized = TRUE;

    return TRUE;
}

VOID AVrfFuzzProcessDetach(
    VOID
    )
{
    if (!AVrfpFuzzContext.Initialized)
    {
        return;
    }

    RtlDeleteCriticalSection(&AVrfpFuzzContext.CriticalSection);

    AVrfpFuzzContext.Initialized = FALSE;
}
