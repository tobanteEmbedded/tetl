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
#include "etl/charconv.hpp"
#include "etl/iterator.hpp"
#include "etl/string_view.hpp"

#include "catch2/catch_template_test_macros.hpp"

using namespace etl::string_view_literals;

TEST_CASE("charconv: chars_format", "[charconv]")
{
    CHECK(etl::chars_format::scientific != etl::chars_format::hex);
    CHECK(etl::chars_format::scientific != etl::chars_format::fixed);
    CHECK(etl::chars_format::scientific != etl::chars_format::general);

    CHECK(etl::chars_format::hex != etl::chars_format::scientific);
    CHECK(etl::chars_format::hex != etl::chars_format::fixed);
    CHECK(etl::chars_format::hex != etl::chars_format::general);

    CHECK(etl::chars_format::fixed != etl::chars_format::scientific);
    CHECK(etl::chars_format::fixed != etl::chars_format::hex);
    CHECK(etl::chars_format::fixed != etl::chars_format::general);

    CHECK(etl::chars_format::general != etl::chars_format::scientific);
    CHECK(etl::chars_format::general != etl::chars_format::hex);
    CHECK(etl::chars_format::general != etl::chars_format::fixed);
}

TEST_CASE("charconv: to_chars_result", "[charconv]")
{
    SECTION("default")
    {
        auto lhs = etl::to_chars_result { nullptr, etl::errc {} };
        auto rhs = etl::to_chars_result { nullptr, etl::errc {} };
        CHECK(lhs == rhs);
    }

    SECTION("char buffer")
    {
        char buffer[16] = {};
        auto lhs        = etl::to_chars_result { buffer, etl::errc {} };
        auto rhs        = etl::to_chars_result { buffer, etl::errc {} };
        CHECK(lhs == rhs);
    }
}

TEST_CASE("charconv: from_chars_result", "[charconv]")
{
    SECTION("default")
    {
        auto lhs = etl::from_chars_result { nullptr, etl::errc {} };
        auto rhs = etl::from_chars_result { nullptr, etl::errc {} };
        CHECK(lhs == rhs);
    }

    SECTION("char buffer")
    {
        char buffer[16] = {};
        auto lhs        = etl::from_chars_result { buffer, etl::errc {} };
        auto rhs        = etl::from_chars_result { buffer, etl::errc {} };
        CHECK(lhs == rhs);
    }
}

TEMPLATE_TEST_CASE("charconv: from_chars<Integer>", "[charconv]", char,
    unsigned char, signed char, unsigned short, short, unsigned int, int,
    unsigned long, long, unsigned long long, long long)
{
    auto val       = TestType {};
    auto const one = "1"_sv;
    CHECK(etl::from_chars(one.begin(), one.end(), val).ptr != nullptr);
    CHECK(val == 1);
    auto const two = "2"_sv;
    CHECK(etl::from_chars(two.begin(), two.end(), val).ptr != nullptr);
    CHECK(val == 2);
    auto const nein = "99"_sv;
    CHECK(etl::from_chars(nein.begin(), nein.end(), val).ptr != nullptr);
    CHECK(val == 99);
}
