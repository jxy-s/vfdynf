/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#include <Windows.h>
#include <iostream>
#include <assert.h>

#define LogPrintID(format, ...)                                               \
    printf("[%04x:%04x %04x] " format "\n",                                   \
           (USHORT)GetCurrentProcessId(),                                     \
           (USHORT)GetCurrentThreadId(),                                      \
           (USHORT)Id,                                                        \
           __VA_ARGS__)

#define LogPrint(format, ...)                                                 \
    printf("[%04x:%04x     ] " format "\n",                                   \
           (USHORT)GetCurrentProcessId(),                                     \
           (USHORT)GetCurrentThreadId(),                                      \
           __VA_ARGS__)

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
        LogPrintID("caught allocation failure");
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
        LogPrintID("caught heap allocate exception");
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

void DoInPageTestDataFile(uint32_t Id)
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
        LogPrintID("failed to open data file");
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
        LogPrintID("failed to create data section");
        goto Exit;
    }

    address = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!address)
    {
        LogPrintID("failed to map data section");
        goto Exit;
    }

    __try
    {
        memcpy(buffer, address, sizeof(buffer));

        if (*(PUSHORT)buffer != IMAGE_DOS_SIGNATURE)
        {
            LogPrintID("caught mmap fuzz for data file");
        }
    }
    __except (InPageExceptionFilter(GetExceptionInformation()))
    {
        LogPrintID("caught in-page failure for data file");
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

void DoInPageTestImageFile(uint32_t Id)
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
        LogPrintID("failed to open image file");
        goto Exit;
    }

    section = CreateFileMappingW(file,
                                 NULL,
                                 PAGE_READONLY | SEC_IMAGE,
                                 0,
                                 0,
                                 NULL);
    if (!section)
    {
        LogPrintID("failed to create image section");
        goto Exit;
    }

    address = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!address)
    {
        LogPrintID("failed to map image section");
        goto Exit;
    }

    __try
    {
        memcpy(buffer, address, sizeof(buffer));

        if (*(PUSHORT)buffer != IMAGE_DOS_SIGNATURE)
        {
            //
            // N.B. we choose not to inject fuzzing for image files
            //
            LogPrintID("FAILURE, caught mmap fuzz for image file");
            DebugBreak();
        }
    }
    __except (InPageExceptionFilter(GetExceptionInformation()))
    {
        //
        // N.B. we choose to not inject in-page errors for image files
        //
        LogPrintID("FAILURE, caught in-page failure for image file");
        DebugBreak();
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


void DoInPageTestImageFileNoExecute(uint32_t Id)
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
        LogPrintID("failed to open image (no execute) file");
        goto Exit;
    }

    section = CreateFileMappingW(file,
                                 NULL,
                                 PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
                                 0,
                                 0,
                                 NULL);
    if (!section)
    {
        LogPrintID("failed to create image (no execute) section");
        goto Exit;
    }

    address = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!address)
    {
        LogPrintID("failed to map image (no execute) section");
        goto Exit;
    }

    __try
    {
        memcpy(buffer, address, sizeof(buffer));

        if (*(PUSHORT)buffer != IMAGE_DOS_SIGNATURE)
        {
            LogPrintID("caught mmap fuzz for image (no execute) file");
        }
    }
    __except (InPageExceptionFilter(GetExceptionInformation()))
    {
        LogPrintID("caught in-page failure for image (no execute) file");
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

void DoInPageTestPagingFile(uint32_t Id)
{
    HANDLE section;
    PVOID address;
    BYTE buffer[512];

    section = NULL;
    address = NULL;

    section = CreateFileMappingW(INVALID_HANDLE_VALUE,
                                 NULL,
                                 PAGE_READWRITE | SEC_COMMIT,
                                 0,
                                 0x4000,
                                 L"TestVFDYNFSection");
    if (!section)
    {
        LogPrintID("failed to create paging file section");
        goto Exit;
    }

    address = MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!address)
    {
        LogPrintID("failed to map paging file section");
        goto Exit;
    }

    __try
    {
        memcpy(buffer, address, sizeof(buffer));
    }
    __except (InPageExceptionFilter(GetExceptionInformation()))
    {
        //
        // N.B. we should not inject in-page failures for paging file mappings
        //
        LogPrintID("FAILURE, caught in-page failure for paging file");
        DebugBreak();
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
}

void DoReadFileTest(uint32_t Id)
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
        LogPrintID("failed to open data file");
        goto Exit;
    }

    ULONG bytesRead;
    if (!ReadFile(file, buffer, sizeof(buffer), &bytesRead, NULL))
    {
        LogPrintID("failed to read file");
        goto Exit;
    }

    if (bytesRead != sizeof(buffer))
    {
        LogPrintID("failed to read all requested bytes");
    }

    if (bytesRead < sizeof(IMAGE_DOS_SIGNATURE))
    {
        LogPrintID("failed to read enough data");
    }
    else if (*(PUSHORT)buffer != IMAGE_DOS_SIGNATURE)
    {
        LogPrintID("caught file read fuzzing");
    }

Exit:

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
}

void DoRegTest(uint32_t Id, PCWSTR ValueName, ULONG Type, PVOID Data, ULONG DataSize)
{
    LSTATUS status;
    HKEY key;
    DWORD type;
    BYTE buffer[1000];
    DWORD dataSize;

    assert(DataSize <= sizeof(buffer));

    status = RegCreateKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\testdynf", &key);
    if (status == ERROR_SUCCESS)
    {
        RegCloseKey(key);
    }
    else
    {
        LogPrintID("failed to create registry key");
    }

    status = RegOpenKeyExW(HKEY_CURRENT_USER,
                           L"SOFTWARE\\testdynf",
                           0,
                           KEY_ALL_ACCESS,
                           &key);
    if (status != ERROR_SUCCESS)
    {
        LogPrintID("failed to open registry key");
        key = NULL;
        goto Exit;
    }

    dataSize = sizeof(buffer);
    status = RegQueryValueExW(key,
                              ValueName,
                              NULL,
                              &type,
                              buffer,
                              &dataSize);
    if (status == ERROR_SUCCESS)
    {
        if (dataSize != DataSize)
        {
            LogPrintID("caught registry size fuzzing");
        }
        else if (memcmp(buffer, Data, DataSize))
        {
            LogPrintID("caught registry data fuzzing");
            // Will verifier stop, uncomment for testing.
            //RegSetValueExW(key, ValueName, 0, Type, buffer, sizeof(buffer));
        }
    }
    else
    {
        LogPrintID("failed to query registry key");
    }

    status = RegSetValueExW(key,
                            ValueName,
                            0,
                            Type,
                            (PBYTE)Data,
                            DataSize);
    if (status != ERROR_SUCCESS)
    {
        LogPrintID("failed to set registry key");
    }

Exit:

    if (key)
    {
        RegCloseKey(key);
    }
}

void LoadUnloadLibraryTest(uint32_t Id)
{
    HMODULE module;

    module = LoadLibraryW(L"cfgmgr32.dll");
    if (!module)
    {
        LogPrintID("failed to load library");
        return;
    }

    FreeLibrary(module);
}

void DoInPageTest(uint32_t Id)
{
    DoInPageTestDataFile(Id);
    DoInPageTestImageFile(Id);
    DoInPageTestImageFileNoExecute(Id);
    DoInPageTestPagingFile(Id);
}

static DWORD RegDword = 0x11223344;
static WCHAR RegString[] = L"String to store in the registry";

void DoTest(uint32_t Id)
{
    DoStlTest(Id);
    DoHeapExceptionTest(Id);
    DoInPageTest(Id);
    DoReadFileTest(Id);
    DoRegTest(Id, L"TestDWORD", REG_DWORD, &RegDword, sizeof(ULONG));
    DoRegTest(Id, L"TestString", REG_SZ, (PVOID)RegString, sizeof(RegString));
    LoadUnloadLibraryTest(Id);
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

#define CONCURRENCY              3
#define LOOP_LIMIT               10
#define ENABLE_TEST_TYPE_DEFAULT 1
#define ENABLE_TEST_TYPE_RECURSE 1
#define ENABLE_TEST_TYPE_STRESS  1

#define DO_RECURSE_TEST(x) DoTestRecurse##x(i, i + (LOOP_LIMIT * x))

DWORD WINAPI DoTestDefaultWorker(PVOID Context)
{
    LogPrint("----DEFAULT-------------------------------------------------------");
    for (uint32_t i = 0; i < LOOP_LIMIT; i++)
    {
        DoTest(i);
    }
    LogPrint("------------------------------------------------------------------");

    return 0;
}

DWORD WINAPI DoTestRecurseWorker(PVOID Context)
{
    LogPrint("----RECURSE-------------------------------------------------------");
    for (uint32_t i = 0; i < LOOP_LIMIT; i++)
    {
        DO_RECURSE_TEST(0);
    }
    LogPrint("------------------------------------------------------------------");

    return 0;
}

DWORD WINAPI DoTestStressWorker(PVOID Context)
{
    LogPrint("----STRESS--------------------------------------------------------");
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
    LogPrint("------------------------------------------------------------------");

    return 0;
}

void DoWork(PTHREAD_START_ROUTINE Routine)
{
    ULONG count;
    HANDLE threads[CONCURRENCY];

    for (ULONG i = 0; i < CONCURRENCY; i++)
    {
        threads[i] = CreateThread(NULL, 0, Routine, NULL, 0, NULL);
        if (!threads[i])
        {
            LogPrint("failed to create thread");
        }
    }

    count = 0;

    for (ULONG i = 0; i < CONCURRENCY; i++)
    {
        if (threads[i])
        {
            count++;
        }
        else
        {
            memmove(&threads[i],
                    &threads[i + 1],
                    (CONCURRENCY - (i + 1)) * sizeof(HANDLE));
        }
    }

    WaitForMultipleObjects(count, threads, TRUE, INFINITE);

    for (ULONG i = 0; i < count; i++)
    {
        CloseHandle(threads[i]);
    }
}

void DoTestDefault()
{
    DoWork(DoTestDefaultWorker);
}

void DoTestRecurse()
{
    DoWork(DoTestRecurseWorker);
}

void DoTestStress()
{
    DoWork(DoTestStressWorker);
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