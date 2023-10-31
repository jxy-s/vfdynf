/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <Windows.h>
#include <iostream>
#include <assert.h>

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

#define RECUSE_TEST(x)                                                        \
    void DoTestRecurse##x(uint32_t RecuseTo, uint32_t Id)                     \
    {                                                                         \
        if (RecuseTo > 0)                                                     \
        {                                                                     \
            DoTestRecurse##x(RecuseTo - 1, Id);                               \
            return;                                                           \
        }                                                                     \
        DoTest(Id);                                                           \
    }

RECUSE_TEST(0);
RECUSE_TEST(1);
RECUSE_TEST(2);
RECUSE_TEST(3);
RECUSE_TEST(4);
RECUSE_TEST(5);
RECUSE_TEST(6);
RECUSE_TEST(7);
RECUSE_TEST(8);
RECUSE_TEST(9);

#define LOOP_LIMIT               10
#define ENABLE_TEST_TYPE_DEFAULT 1
#define ENABLE_TEST_TYPE_RECURSE 1
#define ENABLE_TEST_TYPE_STRESS  1
#define ENABLE_TEST_IN_PAGE      1

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

void DoTestInPage()
{
    puts("----IN-PAGE-------------------------------------------------------");
    for (uint32_t i = 0; i < LOOP_LIMIT; i++)
    {
        DoInPageTest(i);
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

#if ENABLE_TEST_IN_PAGE
        DoTestInPage();
#endif
    }

    return EXIT_SUCCESS;
}