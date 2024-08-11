/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <Windows.h>
#include <stdio.h>

#define TESTDYNF_REG_DATA 0x11223344
void DoRegTest(ULONG Id)
{
    LSTATUS status;
    HKEY key;
    DWORD type;
    DWORD data;
    DWORD dataSize;

    status = RegCreateKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\testdynf", &key);
    if (status == ERROR_SUCCESS)
    {
        RegCloseKey(key);
    }
    else
    {
        printf("[%lu] failed to create registry key\n", Id);
    }

    status = RegOpenKeyExW(HKEY_CURRENT_USER,
                           L"SOFTWARE\\testdynf",
                           0,
                           KEY_ALL_ACCESS,
                           &key);
    if (status != ERROR_SUCCESS)
    {
        printf("[%lu] failed to open registry key\n", Id);
        key = NULL;
        goto Exit;
    }

    dataSize = sizeof(data);
    status = RegQueryValueExW(key,
                              L"TestValue",
                              NULL,
                              &type,
                              (PBYTE)&data,
                              &dataSize);
    if (status == ERROR_SUCCESS)
    {
        if (dataSize != sizeof(data))
        {
            printf("[%lu] caught registry size fuzzing\n", Id);
        }
        else if (data != TESTDYNF_REG_DATA)
        {
            printf("[%lu] caught registry data fuzzing\n", Id);
        }
    }
    else
    {
        printf("[%lu] failed to query registry key\n", Id);
    }

    data = TESTDYNF_REG_DATA;
    status = RegSetValueExW(key,
                            L"TestValue",
                            0,
                            REG_DWORD,
                            (PBYTE)&data,
                            sizeof(data));
    if (status != ERROR_SUCCESS)
    {
        printf("[%lu] failed to set registry key\n", Id);
    }

Exit:

    if (key)
    {
        RegCloseKey(key);
    }
}

void DoTest(ULONG Id)
{
    DoRegTest(Id);
}

#define RECURSE_TEST(x)                                                       \
    void DoTestRecurse##x(ULONG RecuseTo, ULONG Id)                           \
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
    for (ULONG i = 0; i < LOOP_LIMIT; i++)
    {
        DoTest(i);
    }
    puts("------------------------------------------------------------------");
}

void DoTestRecurse()
{
    puts("----RECURSE-------------------------------------------------------");
    for (ULONG i = 0; i < LOOP_LIMIT; i++)
    {
        DO_RECURSE_TEST(0);
    }
    puts("------------------------------------------------------------------");
}

void DoTestStress()
{
    puts("----STRESS--------------------------------------------------------");
    for (ULONG i = 0; i < LOOP_LIMIT; i++)
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
