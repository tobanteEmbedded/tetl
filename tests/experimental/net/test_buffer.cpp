/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "catch2/catch_template_test_macros.hpp"

#include "etl/array.hpp"                           // for array
#include "etl/experimental/net/buffer.hpp"         // for make_buffer
#include "etl/experimental/net/buffer_const.hpp"   // for const_buffer, ope...
#include "etl/experimental/net/buffer_mutable.hpp" // for mutable_buffer

TEST_CASE(
    "experimental/net/mutable_buffer: construct empty", "[experimental][net]")
{
    auto const buffer = etl::experimental::net::mutable_buffer {};
    REQUIRE(buffer.data() == nullptr);
    REQUIRE(buffer.size() == 0);
}

TEST_CASE(
    "experimental/net/mutable_buffer: construct range", "[experimental][net]")
{
    auto mem    = etl::array<char, 32> {};
    auto buffer = etl::experimental::net::make_buffer(mem.data(), mem.size());
    REQUIRE(mem.data() == buffer.data());
    REQUIRE(mem.size() == buffer.size());
}

TEST_CASE("experimental/net/mutable_buffer: operator+=", "[experimental][net]")
{
    auto mem    = etl::array<char, 32> {};
    auto buffer = etl::experimental::net::make_buffer(mem.data(), mem.size());
    buffer += 4;
    REQUIRE(mem.data() != buffer.data());
}

TEST_CASE("experimental/net/mutable_buffer: operator+", "[experimental][net]")
{
    auto mem    = etl::array<char, 32> {};
    auto buffer = etl::experimental::net::make_buffer(mem.data(), mem.size());

    WHEN("offset is on rhs")
    {
        auto newBuf = buffer + 4;
        REQUIRE(newBuf.size() == buffer.size() - 4);
    }

    WHEN("offset is on lhs")
    {
        auto newBuf = 8 + buffer;
        REQUIRE(newBuf.size() == buffer.size() - 8);
    }
}

TEST_CASE(
    "experimental/net/const_buffer: construct empty", "[experimental][net]")
{
    auto const buffer = etl::experimental::net::const_buffer {};
    REQUIRE(buffer.data() == nullptr);
    REQUIRE(buffer.size() == 0);
}

TEST_CASE(
    "experimental/net/const_buffer: construct range", "[experimental][net]")
{
    auto const mem = etl::array<char, 32> {};
    auto buffer = etl::experimental::net::make_buffer(mem.data(), mem.size());
    REQUIRE(mem.data() == buffer.data());
    REQUIRE(mem.size() == buffer.size());
}

TEST_CASE("experimental/net/const_buffer: operator+=", "[experimental][net]")
{
    auto const mem = etl::array<char, 32> {};
    auto buffer = etl::experimental::net::make_buffer(mem.data(), mem.size());
    buffer += 4;
    REQUIRE(mem.data() != buffer.data());
    REQUIRE(mem.size() - 4 == buffer.size());
}

TEST_CASE("experimental/net/const_buffer: operator+", "[experimental][net]")
{
    auto const mem = etl::array<char, 32> {};
    auto buffer = etl::experimental::net::make_buffer(mem.data(), mem.size());

    WHEN("offset is on rhs")
    {
        auto newBuf = buffer + 4;
        REQUIRE(newBuf.size() == buffer.size() - 4);
    }

    WHEN("offset is on lhs")
    {
        auto newBuf = 8 + buffer;
        REQUIRE(newBuf.size() == buffer.size() - 8);
    }
}