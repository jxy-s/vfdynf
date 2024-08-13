/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>
#include <delayld.h>

#define VFDYNF_FUZZ_BLOCK_SIZE          (0x1000 / 4)
#define VFDYNF_RAND_VECTOR_SIZE         0x4000
#define VFDYNF_FUZZ_MMAP_COUNT          1024
#define VFDYNF_FUZZED_BUFFERS_COUNT     1024
#define VFDYNF_FUZZ_CLASSIFY_MIN_LENGTH (sizeof(ULONG64) * 2)
#define VFDYNF_FUZZ_CLASSIFY_SENTINELS  5

typedef struct _VFDYNF_FUZZ_MMAP_ENTRY
{
    PVOID OriginalBaseAddress;
    PVOID FuzzedBaseAddress;
} VFDYNF_FUZZ_MMAP_ENTRY, *PVFDYNF_FUZZ_MMAP_ENTRY;

typedef struct _VFDYNF_FUZZED_BUFFER_ENTRY
{
    ULONG TypeIndex;
    PVOID Address;
    SIZE_T Size;
} VFDYNF_FUZZED_BUFFER_ENTRY, *PVFDYNF_FUZZED_BUFFER_ENTRY;

typedef enum _VFDYNF_FUZZ_BUFFER_CLASS
{
    VFDynfBufferData,
    VFDynfBufferUnicode,
    VFDynfBufferAnsi,
} VFDYNF_FUZZ_BUFFER_CLASS, *PVFDYNF_FUZZ_BUFFER_CLASS;

typedef struct _VFDYNF_FUZZ_CONTEXT
{
    BOOLEAN Initialized;
    volatile LONG Index;
    BYTE Vector[0x4000];
    RTL_CRITICAL_SECTION CriticalSection;
    ULONG MMapEntryCount;
    VFDYNF_FUZZ_MMAP_ENTRY MMapEntries[VFDYNF_FUZZ_MMAP_COUNT];
    volatile LONG BufferIndex;
    VFDYNF_FUZZED_BUFFER_ENTRY FuzzedBuffers[VFDYNF_FUZZED_BUFFERS_COUNT];
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
    .BufferIndex = 0,
    .FuzzedBuffers = { 0 },
};

// https://github.com/winsiderss/systeminformer/blob/master/phlib/data.c
static BOOLEAN AVrfpCharIsPrintable[256] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, /* 0 - 15 */ // TAB, LF and CR are printable
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 16 - 31 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* ' ' - '/' */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* '0' - '9' */
    1, 1, 1, 1, 1, 1, 1, /* ':' - '@' */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 'A' - 'Z' */
    1, 1, 1, 1, 1, 1, /* '[' - '`' */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 'a' - 'z' */
    1, 1, 1, 1, 0, /* '{' - 127 */ // DEL is not printable
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 128 - 143 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 144 - 159 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 160 - 175 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 176 - 191 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 192 - 207 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 208 - 223 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 224 - 239 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 /* 240 - 255 */
};

static UNICODE_STRING AvrfpFuzzStringTableW[] =
{
    RTL_CONSTANT_STRING(L"\0"),
    RTL_CONSTANT_STRING(L"\0"),
    RTL_CONSTANT_STRING(L"\0"),
    RTL_CONSTANT_STRING(L"\0"),
    RTL_CONSTANT_STRING(L"%s"),
    RTL_CONSTANT_STRING(L"\\"),
    RTL_CONSTANT_STRING(L"C:\\"),
    RTL_CONSTANT_STRING(L"\\\\"),
    RTL_CONSTANT_STRING(L","),
    RTL_CONSTANT_STRING(L":"),
    RTL_CONSTANT_STRING(L"%"),
    RTL_CONSTANT_STRING(L"(("),
    RTL_CONSTANT_STRING(L"{{"),
    RTL_CONSTANT_STRING(L"%APPDATA%"),
};

static ANSI_STRING AvrfpFuzzStringTableA[] =
{
    RTL_CONSTANT_STRING("\0"),
    RTL_CONSTANT_STRING("\0"),
    RTL_CONSTANT_STRING("\0"),
    RTL_CONSTANT_STRING("\0"),
    RTL_CONSTANT_STRING("%s"),
    RTL_CONSTANT_STRING("\\"),
    RTL_CONSTANT_STRING("C:\\"),
    RTL_CONSTANT_STRING("\\\\"),
    RTL_CONSTANT_STRING(","),
    RTL_CONSTANT_STRING(";"),
    RTL_CONSTANT_STRING("%"),
    RTL_CONSTANT_STRING("(("),
    RTL_CONSTANT_STRING("{{"),
    RTL_CONSTANT_STRING("%APPDATA%"),
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

    index = (ULONG)(InterlockedIncrement(&AVrfpFuzzContext.Index) - 1);

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

VFDYNF_FUZZ_BUFFER_CLASS AVrfpFuzzClassifyBuffer(
    _In_reads_bytes_(*Length) PBYTE Buffer,
    _Inout_ PSIZE_T Length
    )
{
    SIZE_T length;
    SIZE_T printable;
    SIZE_T sentinels;
    SIZE_T percent;

    length = *Length;

    if (length <= VFDYNF_FUZZ_CLASSIFY_MIN_LENGTH)
    {
        return VFDynfBufferData;
    }

    sentinels = 0;
    printable = 0;

    for (ULONG i = 0; i < length; i++)
    {
        if (AVrfpCharIsPrintable[Buffer[i]])
        {
            printable++;
        }

        if (Buffer[i] == VFDYNF_FUZZ_SENTINEL)
        {
            sentinels++;
        }
        else
        {
            sentinels = 0;
        }

        if (sentinels >= VFDYNF_FUZZ_CLASSIFY_SENTINELS)
        {
            //
            // Likely at our memory fill, stop counting and clamp the length.
            //
            length = (((SIZE_T)i - VFDYNF_FUZZ_CLASSIFY_SENTINELS) + 1);
            printable -= sentinels;
            *Length = length;
            break;
        }
    }

    //
    // Check if we've clamped the length too small.
    //
    if (length <= VFDYNF_FUZZ_CLASSIFY_MIN_LENGTH)
    {
        return VFDynfBufferData;
    }

    C_ASSERT(VFDYNF_FUZZ_CLASSIFY_MIN_LENGTH > 2);

    percent = ((printable * 100) / length);
    if (percent >= 79)
    {
        return VFDynfBufferAnsi;
    }

    percent = ((printable * 100) / (length / 2));
    if ((percent <= 100) && (percent >= 94))
    {
        return VFDynfBufferUnicode;
    }

    return VFDynfBufferData;
}

VOID AVrfpFuzzGetBufferRange(
    _In_ SIZE_T Length,
    _Out_ PULONG Start,
    _Out_ PULONG End
    )
{
    ULONG offsets[2];

    offsets[0] = AVrfFuzzRandom() % Length;
    offsets[1] = AVrfFuzzRandom() % Length;

    *Start = offsets[0] < offsets[1] ? offsets[0] : offsets[1];
    *End = offsets[0] > offsets[1] ? offsets[0] : offsets[1];
}

VOID AVrfpFuzzBuffer(
    _Inout_bytecount_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    )
{
    PBYTE bufferBytes;
    SIZE_T bufferLength;
    ULONG corruptionBlocks;
    VFDYNF_FUZZ_BUFFER_CLASS bufferClass;

    if (!AVrfProperties.FuzzCorruptionBlocks)
    {
        return;
    }

    bufferBytes = Buffer;
    bufferLength = Length;
    corruptionBlocks = (1 + (AVrfFuzzRandom() % AVrfProperties.FuzzCorruptionBlocks));

    bufferClass = AVrfpFuzzClassifyBuffer(bufferBytes, &bufferLength);

    for (ULONG i = 0; i < corruptionBlocks; i++)
    {
        if (AVrfFuzzProbability(AVrfProperties.FuzzChaosProbability))
        {
            ULONG start;
            ULONG end;

            AVrfpFuzzGetBufferRange(bufferLength, &start, &end);

            if (AVrfFuzzProbability(100000))
            {
                if (AVrfFuzzProbability(500000))
                {
                    RtlFillMemory(&bufferBytes[start], end - start, 0x00);
                }
                else
                {
                    RtlFillMemory(&bufferBytes[start], end - start, 0xff);
                }
            }
            else
            {
                while (start < end)
                {
                    bufferBytes[start++] = (BYTE)AVrfFuzzRandom();
                }
            }
        }
        else if (bufferClass == VFDynfBufferUnicode)
        {
            ULONG start;
            ULONG end;
            PUNICODE_STRING string;

            AVrfpFuzzGetBufferRange(bufferLength, &start, &end);

            string = &AvrfpFuzzStringTableW[AVrfFuzzRandom() % ARRAYSIZE(AvrfpFuzzStringTableW)];

            if (start % 2)
            {
                start++;
                end++;
            }

            if ((start < bufferLength) && (string->Length <= (end - start)))
            {
                memcpy(&bufferBytes[start], string->Buffer, string->Length);
            }
        }
        else if (bufferClass == VFDynfBufferAnsi)
        {
            ULONG start;
            ULONG end;
            PANSI_STRING string;

            AVrfpFuzzGetBufferRange(bufferLength, &start, &end);

            string = &AvrfpFuzzStringTableA[AVrfFuzzRandom() % ARRAYSIZE(AvrfpFuzzStringTableW)];

            if (string->Length <= (end - start))
            {
                memcpy(&bufferBytes[start], string->Buffer, string->Length);
            }
        }
        else
        {
            ULONG pos;

            pos = AVrfFuzzRandom() % bufferLength;

            if (AVrfFuzzProbability(250000))
            {
                pos &= 0xfffffffc;
            }

            if ((pos + 3) >= bufferLength)
            {
                bufferBytes[pos] ^= (BYTE)(1 + AVrfFuzzRandom());
                continue;
            }

            switch (AVrfFuzzRandom() % 13)
            {
                case 1: // off by a bit
                {
                    *(PULONG)&bufferBytes[pos] += 512 - (ULONG)(AVrfFuzzRandom() % 1024);
                    break;
                }
                case 2: // off by multiple of four
                {
                    *(PULONG)&bufferBytes[pos] += 4 * (512 - (ULONG)(AVrfFuzzRandom() % 1024));
                    break;
                }
                case 3: // negative one
                {
                    *(PULONG)&bufferBytes[pos] = 0xffffffff;
                    break;
                }
                case 4: // small negative
                {
                    *(PULONG)&bufferBytes[pos] = -(LONG)(AVrfFuzzRandom() % 25);
                    break;
                }
                case 5: // zero
                {
                    *(PULONG)&bufferBytes[pos] = 0;
                    break;
                }
                case 6: // negate
                {
                    *(PULONG)&bufferBytes[pos] = -(*(PLONG)&bufferBytes[pos]);
                    break;
                }
                case 7: // compliment
                {
                    *(PULONG)&bufferBytes[pos] = ~(*(PLONG)&bufferBytes[pos]);
                    break;
                }
                case 8: // treat position as offset
                {
                    *(PULONG)&bufferBytes[pos] = (ULONG)pos + 4 * (128 - (ULONG)(AVrfFuzzRandom() % 256));
                    break;
                }
                case 9: // copy alternate dword
                {
                    *(PULONG)&bufferBytes[pos] = *(PULONG)&bufferBytes[AVrfFuzzRandom() % (bufferLength - 3)];
                    break;
                }
                default: // random dword
                {
                    *(PULONG)&bufferBytes[pos] = (ULONG)(1 + AVrfFuzzRandom());
                    break;
                }
            }
        }
    }
}

VOID AvrfpTrackFuzzedBuffer(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG TypeIndex
    )
{
    ULONG index;
    PVFDYNF_FUZZED_BUFFER_ENTRY entry;

    index = (ULONG)(InterlockedIncrement(&AVrfpFuzzContext.BufferIndex) - 1);

    entry = &AVrfpFuzzContext.FuzzedBuffers[index % VFDYNF_FUZZED_BUFFERS_COUNT];

    entry->TypeIndex = TypeIndex;
    entry->Address = Buffer;
    entry->Size = Length;
}

VOID AVrfFuzzBuffer(
    _Inout_bytecount_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG TypeIndex
    )
{
    SIZE_T remaining;

    AvrfpTrackFuzzedBuffer(Buffer, Length, TypeIndex);

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

        AVrfFuzzBuffer(baseAddress,
                       RegionSize,
                       VFDYNF_FAULT_TYPE_INDEX_FUZZ_MMAP);
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
