/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <vfdynf.h>

#define STACK_BUCKET_INITIAL_CAPACITY (1024 / sizeof(AVRF_STACK_ENTRY))
#define STACK_BUCKET_GROWTH_FACTOR    (2)

typedef struct _AVRF_STACK_ENTRY_SEARCH
{
    ULONG Hash;
    PAVRF_STACK_ENTRY Before;
} AVRF_STACK_ENTRY_SEARCH, *PAVRF_STACK_ENTRY_SEARCH;

static int __cdecl AVrfpCompareStackEntry(
    void const* Search,
    void const* Entry
    )
{
    PAVRF_STACK_ENTRY_SEARCH search;
    PAVRF_STACK_ENTRY entry;

    search = (PAVRF_STACK_ENTRY_SEARCH)Search;
    entry = (PAVRF_STACK_ENTRY)Entry;

    if (search->Hash == entry->Hash)
    {
        return 0;
    }

    if (search->Hash > entry->Hash)
    {
        return 1;
    }

    search->Before = entry;
    return -1;
}

_Must_inspect_result_
_Success_(return != NULL)
PAVRF_STACK_ENTRY AVrfpLookupStackEntryInBucket(
    _In_ PAVRF_STACK_TABLE_BUCKET Bucket,
    _In_ ULONG Hash
    )
{
    PAVRF_STACK_ENTRY entry;
    AVRF_STACK_ENTRY_SEARCH search;
    search.Hash = Hash;
    search.Before = NULL;

    entry = (PAVRF_STACK_ENTRY)bsearch(&search,
                                       Bucket->Entries,
                                       Bucket->Count,
                                       sizeof(AVRF_STACK_ENTRY),
                                       AVrfpCompareStackEntry);
    if (!entry)
    {
        entry = search.Before;
    }

    return entry;
}

_Must_inspect_result_
_Success_(return != NULL)
PAVRF_STACK_ENTRY AVrfLookupStackEntry(
    _Inout_ PAVRF_STACK_TABLE Table,
    _In_ ULONG Hash
    )
{
    PAVRF_STACK_TABLE_BUCKET bucket;

    //
    // N.B. this function returns the entry if it exists, or the entry before
    // where a new one should be inserted
    //
    // The caller should check for null and compare the hash to determine
    // if the entry exists.
    //
    // If the entry doesn't exist they should pass the return value to insert
    // a new entry into the necessary position (yes even if it's null).
    //

    bucket = &Table->Buckets[Hash % STACK_BUCKET_COUNT];

    return AVrfpLookupStackEntryInBucket(bucket, Hash);
}

_Must_inspect_impl_
_Success_(return != NULL)
PAVRF_STACK_ENTRY AVrfpInsertStackEntryInBucket(
    _In_ PAVRF_STACK_TABLE_BUCKET Bucket,
    _In_opt_ PAVRF_STACK_ENTRY Before,
    _In_ ULONG Hash
    )
{
    if (Bucket->Count >= Bucket->Capacity)
    {
        PAVRF_STACK_ENTRY entries;
        ULONG capacity;

        if (!Bucket->Capacity)
        {
            capacity = STACK_BUCKET_INITIAL_CAPACITY;
        }
        else
        {
            capacity = (Bucket->Capacity * STACK_BUCKET_GROWTH_FACTOR);
        }

        entries = (PAVRF_STACK_ENTRY)RtlAllocateHeap(
                                          RtlProcessHeap(),
                                          0,
                                          capacity * sizeof(AVRF_STACK_ENTRY));
        if (!entries)
        {
            return NULL;
        }

        Bucket->Capacity = capacity;

        if (Before)
        {
            Before = &entries[Before - Bucket->Entries];
        }

        if (Bucket->Entries)
        {
            RtlCopyMemory(entries,
                          Bucket->Entries,
                          Bucket->Count * sizeof(AVRF_STACK_ENTRY));

            RtlFreeHeap(RtlProcessHeap(), 0, Bucket->Entries);

            Bucket->Entries = entries;
        }
        else
        {
            Bucket->Entries = entries;
        }
    }

    if (Before)
    {
        ULONG shift;

        shift = Bucket->Count - (ULONG)(Before - Bucket->Entries);

        RtlMoveMemory(Before + 1, Before, shift * sizeof(AVRF_STACK_ENTRY));
    }
    else
    {
        Before = &Bucket->Entries[Bucket->Count];
    }

    Before->Hash = Hash;
    Before->Excluded = FALSE;
    Before->FaultMask = 0;

    Bucket->Count++;

    return Before;
}

_Must_inspect_impl_
_Success_(return != NULL)
PAVRF_STACK_ENTRY AVrfInsertStackEntry(
    _Inout_ PAVRF_STACK_TABLE Table,
    _In_opt_ PAVRF_STACK_ENTRY Before,
    _In_ ULONG Hash
    )
{
    PAVRF_STACK_TABLE_BUCKET bucket;

    bucket = &Table->Buckets[Hash % STACK_BUCKET_COUNT];

    return AVrfpInsertStackEntryInBucket(bucket, Before, Hash);
}

VOID AVrfRemoveStackEntry(
    _Inout_ PAVRF_STACK_TABLE Table,
    _In_ PAVRF_STACK_ENTRY Entry
    )
{
    PAVRF_STACK_TABLE_BUCKET bucket;
    ULONG shift;

    bucket = &Table->Buckets[Entry->Hash % STACK_BUCKET_COUNT];

    shift = bucket->Count - (ULONG)(Entry - bucket->Entries) - 1;

    RtlMoveMemory(Entry, Entry + 1, shift * sizeof(AVRF_STACK_ENTRY));

    bucket->Count--;
}

VOID AVrfClearStackTable(
    _Inout_ PAVRF_STACK_TABLE Table
    )
{
    for (ULONG i = 0; i < STACK_BUCKET_COUNT; i++)
    {
        Table->Buckets[i].Count = 0;
    }
}

VOID AVrfInitializeStackTable(
    _Out_ PAVRF_STACK_TABLE Table
    )
{
    RtlZeroMemory(Table, sizeof(AVRF_STACK_TABLE));
}

VOID AVrfFreeStackTable(
    _Inout_ PAVRF_STACK_TABLE Table
    )
{
    for (ULONG i = 0; i < STACK_BUCKET_COUNT; i++)
    {
        PAVRF_STACK_TABLE_BUCKET bucket;

        bucket = &Table->Buckets[i];

        if (bucket->Entries)
        {
            RtlFreeHeap(RtlProcessHeap(), 0, bucket->Entries);

            bucket->Capacity = 0;
            bucket->Count = 0;
            bucket->Entries = NULL;
        }
    }
}
