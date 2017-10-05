/**
 * MIT License
 *
 * Copyright (c) 2017 Rokas Kupstys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#define HOOKER_IMPLEMENTATION
#include "../hooker.h"

int(*original_call)();

int test_raw_hook1()
{
    char a[] = "padding";
    return &a != nullptr ? 1 : 0;
}

int test_raw_hook2()
{
    char a[] = "padding";
    return &a != nullptr ? 1 : 0;
}

int test_raw_hook_new()
{
    if (original_call)
        return original_call() + 2;
    return 2;
}

TEST_CASE ("RawHook")
{
    REQUIRE(hooker_hook((void*) &test_raw_hook2, (void*)&test_raw_hook_new, HOOKER_HOOK_JMP, 0) == HOOKER_SUCCESS);
    REQUIRE(test_raw_hook2() == 2);
}

TEST_CASE ("SmartHook")
{
    original_call = (int (*)())(hooker_redirect((void*) &test_raw_hook1, (void*)&test_raw_hook_new));
    REQUIRE(original_call != HOOKER_ERROR);
    REQUIRE(test_raw_hook1() == 3);
    hooker_unhook((void*) &test_raw_hook1, (void*)original_call);
    REQUIRE(test_raw_hook1() == 1);
}
