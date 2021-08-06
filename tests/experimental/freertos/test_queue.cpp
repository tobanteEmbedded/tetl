// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#include "catch2/catch_template_test_macros.hpp"

#define TETL_FREERTOS_USE_STUBS
#include "etl/experimental/freertos/queue.hpp"

namespace rtos = etl::experimental::freertos;

TEMPLATE_TEST_CASE("experimental/freertos/queue: construct",
    "[experimental][rtos]", etl::uint8_t, etl::int8_t, etl::uint16_t,
    etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
    float, double, long double)
{
    rtos::queue<TestType, 100> q1 {};
}

TEMPLATE_TEST_CASE("experimental/freertos/queue: capacity",
    "[experimental][rtos]", etl::uint8_t, etl::int8_t, etl::uint16_t,
    etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
    float, double, long double)
{
    rtos::queue<TestType, 1> q1 {};
    REQUIRE(q1.capacity() == 1);
    rtos::queue<TestType, 32> q2 {};
    REQUIRE(q2.capacity() == 32);
    rtos::queue<TestType, 128> q3 {};
    REQUIRE(q3.capacity() == 128);
}

TEMPLATE_TEST_CASE("experimental/freertos/queue: send", "[experimental][rtos]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    rtos::queue<TestType, 1> q1 {};
    // stub always returns false
    REQUIRE(q1.send(1, 0) == false);
}

TEST_CASE("experimental/freertos/queue: receive io/out argument",
    "[experimental][rtos]")
{
    rtos::queue<int, 1> q1 {};
    // stub always returns false
    auto i = int { 0 };
    REQUIRE(q1.receive(i, 0) == false);
}

TEST_CASE(
    "experimental/freertos/queue: receive pair<bool,T>", "[experimental][rtos]")
{
    rtos::queue<int, 1> q1 {};
    // stub always returns false
    auto [success, value] = q1.receive(0);
    REQUIRE(success == false);
    REQUIRE(value == 0);
}

TEST_CASE("experimental/freertos/queue: reset", "[experimental][rtos]")
{
    rtos::queue<int, 1> q1 {};
    REQUIRE(q1.reset() == true);
}

TEST_CASE(
    "experimental/freertos/queue: messages_waiting", "[experimental][rtos]")
{
    rtos::queue<int, 1> q1 {};
    // stub always returns 0
    REQUIRE(q1.messages_waiting() == 0);
}
