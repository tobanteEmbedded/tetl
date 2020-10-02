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

#include "etl/experimental/format/format.hpp"

#include "etl/string.hpp"
#include "etl/string_view.hpp"

#include "catch2/catch.hpp"

TEST_CASE("experimental/format: format_to<char>", "[experimental][format]")
{
    namespace fmt = etl::experimental::format;

    SECTION("no arg")
    {
        auto str    = etl::static_string<32> {};
        auto target = etl::string_view("test");
        fmt::format_to(etl::back_inserter(str), "test");
        CHECK(etl::string_view(str) == target);
    }

    SECTION("no arg escaped")
    {
        auto str_1 = etl::static_string<32> {};
        fmt::format_to(etl::back_inserter(str_1), "{{test}}");
        CHECK(etl::string_view(str_1) == etl::string_view("{test}"));

        auto str_2 = etl::static_string<32> {};
        fmt::format_to(etl::back_inserter(str_2), "{{abc}} {{def}}");
        CHECK(etl::string_view(str_2) == etl::string_view("{abc} {def}"));
    }

    SECTION("single arg")
    {
        auto str    = etl::static_string<32> {};
        auto target = etl::string_view("test");
        fmt::format_to(etl::back_inserter(str), "tes{}", 't');
        CHECK(etl::string_view(str) == target);
    }

    SECTION("escape single arg")
    {
        auto str_1 = etl::static_string<32> {};
        fmt::format_to(etl::back_inserter(str_1), "{} {{test}}", 'a');
        CHECK(etl::string_view(str_1) == etl::string_view("a {test}"));

        auto str_2 = etl::static_string<32> {};
        fmt::format_to(etl::back_inserter(str_2), "{{test}} {}", 'b');
        CHECK(etl::string_view(str_2) == etl::string_view("{test} b"));
    }

    SECTION("replace multiple args")
    {
        auto str    = etl::static_string<32> {};
        auto target = etl::string_view("a b c");
        fmt::format_to(etl::back_inserter(str), "{} {} {}", 'a', 'b', 'c');
        CHECK(etl::string_view(str.begin()) == target);
    }
}

TEST_CASE("experimental/format: format_to_n", "[experimental][format]")
{
    namespace fmt = etl::experimental::format;

    SECTION("escape")
    {
        auto buffer = etl::static_string<32> {};
        auto target = etl::string_view("{abc}");
        auto res = fmt::format_to_n(buffer.data(), (ptrdiff_t)buffer.size(), "{{abc}}");
        CHECK(res.out == buffer.begin() + target.size());
        CHECK(res.size == static_cast<decltype(res.size)>(target.size()));
        CHECK(etl::string_view(buffer.begin()) == target);
    }

    SECTION("replace single arg")
    {
        auto buffer = etl::static_string<32> {};
        auto target = etl::string_view("test");
        auto res = fmt::format_to_n(data(buffer), (ptrdiff_t)buffer.size(), "tes{}", 't');
        CHECK(res.out == buffer.begin() + target.size());
        CHECK(res.size == static_cast<decltype(res.size)>(target.size()));
        CHECK(etl::string_view(buffer.begin()) == target);
    }

    // SECTION("replace multiple args")
    // {
    //     auto buffer  = etl::static_string<32> {};
    //     auto fmt_str = etl::string_view("{} {}");
    //     auto target  = etl::string_view("a b");
    //     auto res     = fmt::format_to_n(buffer.data(), buffer.size(),
    //     fmt_str, 'a', 'b'); CHECK(res.out == buffer.begin() + target.size());
    //     CHECK(res.size == static_cast<decltype(res.size)>(target.size()));
    //     CHECK(etl::string_view(buffer.begin()) == target);
    // }
}