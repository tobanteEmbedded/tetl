/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/
#define TAETL_RTOS_USE_STUBS
#include "taetl/experimental/rtos/queue.hpp"

#include "catch2/catch.hpp"

namespace rtos = taetl::rtos;

TEST_CASE("rtos/queue: construct", "[experimental][rtos]")
{
    rtos::queue<char, 100> q1 {};
    rtos::queue<int, 100> q2 {};
    rtos::queue<float, 100> q3 {};
    rtos::queue<double, 100> q4 {};
    rtos::queue<void*, 100> q5 {};
}

TEST_CASE("rtos/queue: capacity", "[experimental][rtos]")
{
    rtos::queue<int, 1> q1 {};
    REQUIRE(q1.capacity() == 1);
    rtos::queue<float, 32> q2 {};
    REQUIRE(q2.capacity() == 32);
    rtos::queue<taetl::uint64_t, 128> q3 {};
    REQUIRE(q3.capacity() == 128);
}
