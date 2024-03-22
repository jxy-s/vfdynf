/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <Windows.h>
#include <iostream>
#include <assert.h>

void DoStlTest(uint32_t Id)
{
    std::string stuff;

    try
    {
        stuff.assign(
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation "
            "super long string that will require a reallocation ");
    }
    catch (const std::bad_alloc&)
    {
        printf("[%lu] caught allocation failure\n", Id);
    }
}

void DoHeapExceptionTest(uint32_t Id)
{
    PVOID memory;

    __try
    {
        memory = HeapAlloc(GetProcessHeap(),
                           HEAP_GENERATE_EXCEPTIONS,
                           0x1000 * 2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[%lu] caught heap allocate exception\n", Id);
        memory = NULL;
    }

    if (memory)
    {
        HeapFree(GetProcessHeap(), 0, memory);
    }
}

INT InPageExceptionFilter(LPEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_IN_PAGE_ERROR)
    {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void DoInPageTest(uint32_t Id)
{
    HANDLE file;
    HANDLE section;
    PVOID address;
    BYTE buffer[512];

    section = NULL;
    address = NULL;

    file = CreateFileW(L"C:\\Windows\\System32\\notepad.exe",
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        printf("[%lu] failed to open file\n", Id);
        goto Exit;
    }

    section = CreateFileMappingW(file,
                                 NULL,
                                 PAGE_READONLY | SEC_COMMIT,
                                 0,
                                 0,
                                 NULL);
    if (!section)
    {
        printf("[%lu] failed to create section\n", Id);
        goto Exit;
    }

    address = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!address)
    {
        printf("[%lu] failed to map section\n", Id);
        goto Exit;
    }

    __try
    {
        memcpy(buffer, address, sizeof(buffer));
    }
    __except (InPageExceptionFilter(GetExceptionInformation()))
    {
        printf("[%lu] caught in-page failure\n", Id);
    }

Exit:

    if (address)
    {
        UnmapViewOfFile(address);
    }

    if (section)
    {
        CloseHandle(section);
    }

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
}

void DoTest(uint32_t Id)
{
    DoStlTest(Id);
    DoHeapExceptionTest(Id);
    DoInPageTest(Id);
}

#define RECURSE_TEST(x)                                                       \
    void DoTestRecurse##x(uint32_t RecuseTo, uint32_t Id)                     \
    {                                                                         \
        if (RecuseTo > 0)                                                     \
        {                                                                     \
            DoTestRecurse##x(RecuseTo - 1, Id);                               \
            return;                                                           \
        }                                                                     \
        DoTest(Id);                                                           \
    }

RECURSE_TEST(0);
RECURSE_TEST(1);
RECURSE_TEST(2);
RECURSE_TEST(3);
RECURSE_TEST(4);
RECURSE_TEST(5);
RECURSE_TEST(6);
RECURSE_TEST(7);
RECURSE_TEST(8);
RECURSE_TEST(9);

#define LOOP_LIMIT               10
#define ENABLE_TEST_TYPE_DEFAULT 1
#define ENABLE_TEST_TYPE_RECURSE 1
#define ENABLE_TEST_TYPE_STRESS  1

#define DO_RECURSE_TEST(x) DoTestRecurse##x(i, i + (LOOP_LIMIT * x))

void DoTestDefault()
{
    puts("----DEFAULT-------------------------------------------------------");
    for (uint32_t i = 0; i < LOOP_LIMIT; i++)
    {
        DoTest(i);
    }
    puts("------------------------------------------------------------------");
}

void DoTestRecurse()
{
    puts("----RECURSE-------------------------------------------------------");
    for (uint32_t i = 0; i < LOOP_LIMIT; i++)
    {
        DO_RECURSE_TEST(0);
    }
    puts("------------------------------------------------------------------");
}

void DoTestStress()
{
    puts("----STRESS--------------------------------------------------------");
    for (uint32_t i = 0; i < LOOP_LIMIT; i++)
    {
        DO_RECURSE_TEST(0);
        DO_RECURSE_TEST(1);
        DO_RECURSE_TEST(2);
        DO_RECURSE_TEST(3);
        DO_RECURSE_TEST(4);
        DO_RECURSE_TEST(5);
        DO_RECURSE_TEST(6);
        DO_RECURSE_TEST(7);
        DO_RECURSE_TEST(8);
        DO_RECURSE_TEST(9);
    }
    puts("------------------------------------------------------------------");
}

int main(int argc, const char* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    for (;; Sleep(300))
    {
#if ENABLE_TEST_TYPE_DEFAULT
        DoTestDefault();
#endif

#if ENABLE_TEST_TYPE_RECURSE
        DoTestRecurse();
#endif

#if ENABLE_TEST_TYPE_STRESS
        DoTestStress();
#endif
    }

    return EXIT_SUCCESS;
}