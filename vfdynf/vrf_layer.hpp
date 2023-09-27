/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#pragma once

namespace layer
{

extern AVRF_LAYER_DESCRIPTOR g_Descriptor;

int32_t
GetRecursionCount(
    void
    );

class RecursionGuard
{
public:

    ~RecursionGuard(
        void
        );

    RecursionGuard(
        void
        );

};

}
