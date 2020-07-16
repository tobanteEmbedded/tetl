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

// TAETL
#include "taetl/experimental/net/buffer.hpp"

#include "catch2/catch.hpp"

TEST_CASE("experimental/net/mutable_buffer: construct empty", "[experimental][net]")
{
    auto const buffer = taetl::net::mutable_buffer {};
    REQUIRE(buffer.data() == nullptr);
    REQUIRE(buffer.size() == 0);
}

TEST_CASE("experimental/net/mutable_buffer: construct range", "[experimental][net]")
{
    auto mem    = taetl::array<char, 32> {};
    auto buffer = taetl::net::make_buffer(mem.data(), mem.size());
    REQUIRE(mem.data() == buffer.data());
    REQUIRE(mem.size() == buffer.size());
}

TEST_CASE("experimental/net/mutable_buffer: operator+=", "[experimental][net]")
{
    auto mem    = taetl::array<char, 32> {};
    auto buffer = taetl::net::make_buffer(mem.data(), mem.size());
    buffer += 4;
    REQUIRE(mem.data() != buffer.data());
}

TEST_CASE("experimental/net/mutable_buffer: operator+", "[experimental][net]")
{
    auto mem    = taetl::array<char, 32> {};
    auto buffer = taetl::net::make_buffer(mem.data(), mem.size());

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

TEST_CASE("experimental/net/const_buffer: construct empty", "[experimental][net]")
{
    auto const buffer = taetl::net::const_buffer {};
    REQUIRE(buffer.data() == nullptr);
    REQUIRE(buffer.size() == 0);
}

TEST_CASE("experimental/net/const_buffer: construct range", "[experimental][net]")
{
    auto const mem = taetl::array<char, 32> {};
    auto buffer    = taetl::net::make_buffer(mem.data(), mem.size());
    REQUIRE(mem.data() == buffer.data());
    REQUIRE(mem.size() == buffer.size());
}

TEST_CASE("experimental/net/const_buffer: operator+=", "[experimental][net]")
{
    auto const mem = taetl::array<char, 32> {};
    auto buffer    = taetl::net::make_buffer(mem.data(), mem.size());
    buffer += 4;
    REQUIRE(mem.data() != buffer.data());
    REQUIRE(mem.size() - 4 == buffer.size());
}

TEST_CASE("experimental/net/const_buffer: operator+", "[experimental][net]")
{
    auto const mem = taetl::array<char, 32> {};
    auto buffer    = taetl::net::make_buffer(mem.data(), mem.size());

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