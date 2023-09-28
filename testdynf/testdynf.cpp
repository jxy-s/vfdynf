/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <Windows.h>
#include <iostream>
#include <assert.h>

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
}