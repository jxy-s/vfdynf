/*
    Copyright (c) Johnny Shaw. All rights reserved. 
*/
#include <Windows.h>
#include <iostream>

int main(int argc, const char* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    for (;; Sleep(300))
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
            std::cout << "caught allocation failure\n";
        }
    }
}