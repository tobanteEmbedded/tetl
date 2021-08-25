/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
