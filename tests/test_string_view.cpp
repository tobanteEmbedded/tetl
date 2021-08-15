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

#include "etl/string_view.hpp"

#include "etl/cstring.hpp"
#include "etl/string.hpp"

#include "catch2/catch_template_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

using namespace etl::literals;
using namespace Catch::Generators;

TEST_CASE("string_view: string_view::string_view()", "[string_view]")
{
    constexpr auto sv = etl::string_view {};

    REQUIRE(sv.data() == nullptr);
    STATIC_REQUIRE(sv.data() == nullptr);

    REQUIRE(sv.size() == 0);
    STATIC_REQUIRE(sv.size() == 0);

    REQUIRE(sv.length() == 0);
    STATIC_REQUIRE(sv.length() == 0);
}

TEST_CASE("string_view: string_view", "[string_view]")
{
    auto [input, expected] = GENERATE(table<char const*, etl::size_t>({
        { "", 0 },
        { "a", 1 },
        { "ab", 2 },
        { "abc", 3 },
        { "abcd", 4 },
        { "abcde", 5 },
        { "0000000000", 10 },
    }));

    REQUIRE(etl::string_view(input).size() == expected);
    REQUIRE(etl::string_view(input, etl::strlen(input)).size() == expected);

    REQUIRE(etl::string_view(input).length() == expected);
    REQUIRE(etl::string_view(input, etl::strlen(input)).length() == expected);

    REQUIRE(etl::string_view { input }.size() == expected);
    REQUIRE(etl::string_view { input, etl::strlen(input) }.size() == expected);

    REQUIRE(etl::string_view { input }.length() == expected);
    REQUIRE(
        etl::string_view { input, etl::strlen(input) }.length() == expected);

    auto const sv   = etl::string_view { input };
    auto const copy = etl::string_view(begin(sv), end(sv));
    REQUIRE(copy.data() == sv.data());
    REQUIRE(copy.size() == sv.size());
    REQUIRE(copy.length() == sv.length());
    REQUIRE(copy == sv);

    auto original = etl::string_view { input };
    auto other    = "other"_sv;
    original.swap(other);
    REQUIRE(other == etl::string_view { input });
    REQUIRE(original == "other"_sv);
}

TEST_CASE("string_view: construct copy", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv1 = etl::string_view {};
        auto const sv2 = sv1;

        REQUIRE(sv2.data() == nullptr);
        REQUIRE(sv2.size() == 0);
        REQUIRE(sv2.length() == 0);
    }

    WHEN("not empty")
    {
        auto const sv1 = "test"_sv;
        auto const sv2 = sv1;

        REQUIRE_FALSE(sv2.data() == nullptr);
        REQUIRE(sv2.size() == 4);
        REQUIRE(sv2.length() == 4);
    }
}

TEST_CASE("string_view: begin", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv = etl::string_view {};
        REQUIRE(sv.data() == nullptr);
        REQUIRE(sv.begin() == sv.cbegin());
    }

    WHEN("not empty")
    {
        auto const sv = "test"_sv;
        REQUIRE(*sv.begin() == 't');
        REQUIRE(sv.begin() == sv.cbegin());
    }
}

TEST_CASE("string_view: end", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv = etl::string_view {};
        REQUIRE(sv.data() == nullptr);
        REQUIRE(sv.end() == sv.cend());
    }

    WHEN("not empty")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.end() == sv.begin() + 4);
        REQUIRE(sv.end() == sv.cend());
    }
}

TEST_CASE("string_view: rbegin/rend", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv = etl::string_view {};
        CHECK(sv.data() == nullptr);
        CHECK(sv.rend() == sv.crend());
        CHECK(sv.data() == nullptr);
        CHECK(sv.rbegin() == sv.crbegin());
    }

    WHEN("not empty")
    {
        auto const sv = "abc"_sv;
        CHECK(*sv.rbegin() == 'c');
        CHECK(sv.rbegin() == sv.crbegin());
        CHECK(sv.rend() != sv.rbegin());
        CHECK(sv.rend() == sv.crend());
    }
}

TEST_CASE("string_view: ranged-for", "[string_view]")
{
    auto const sv = "test"_sv;
    auto counter  = etl::string_view::size_type { 0 };
    for (auto c : sv) {
        etl::ignore_unused(c);
        counter++;
    }

    REQUIRE(counter == sv.size());
    REQUIRE(counter == 4);
}

TEST_CASE("string_view: operator[]", "[string_view]")
{
    auto const sv1 = "test"_sv;
    REQUIRE(sv1[0] == 't');
    REQUIRE(sv1[1] == 'e');
    REQUIRE(sv1[2] == 's');
    REQUIRE(sv1[3] == 't');

    auto sv2 = etl::string_view { "tobi" };
    REQUIRE(sv2[0] == 't');
    REQUIRE(sv2[1] == 'o');
    REQUIRE(sv2[2] == 'b');
    REQUIRE(sv2[3] == 'i');
}

TEST_CASE("string_view: front", "[string_view]")
{
    auto const sv1 = "test"_sv;
    REQUIRE(sv1.front() == 't');

    auto sv2 = "abc"_sv;
    REQUIRE(sv2.front() == 'a');
}

TEST_CASE("string_view: back", "[string_view]")
{
    auto const sv1 = "test"_sv;
    REQUIRE(sv1.back() == 't');

    auto sv2 = "abc"_sv;
    REQUIRE(sv2.back() == 'c');
}

TEST_CASE("string_view: max_size", "[string_view]")
{
    auto const sv = "test"_sv;
    REQUIRE(sv.max_size() == etl::string_view::size_type(-1));
}

TEST_CASE("string_view: empty", "[string_view]")
{
    auto const t = etl::string_view {};
    REQUIRE(t.empty());

    auto const f = "test"_sv;
    REQUIRE_FALSE(f.empty());
}

TEST_CASE("string_view: remove_prefix", "[string_view]")
{
    WHEN("empty")
    {
        auto sv = etl::string_view {};
        REQUIRE(sv.empty());
        sv.remove_prefix(0);
        REQUIRE(sv.empty());
    }

    WHEN("not empty")
    {
        auto sv = "test"_sv;
        REQUIRE(sv.size() == 4);
        sv.remove_prefix(1);
        REQUIRE(sv.size() == 3);
        REQUIRE(sv[0] == 'e');
    }
}

TEST_CASE("string_view: remove_suffix", "[string_view]")
{
    WHEN("empty")
    {
        auto sv = etl::string_view {};
        REQUIRE(sv.empty());
        sv.remove_suffix(0);
        REQUIRE(sv.empty());
    }

    WHEN("not empty")
    {
        auto sv = "test"_sv;
        REQUIRE(sv.size() == 4);

        sv.remove_suffix(1);
        REQUIRE(sv.size() == 3);
        REQUIRE(sv[0] == 't');
        REQUIRE(sv[1] == 'e');
        REQUIRE(sv[2] == 's');

        sv.remove_suffix(2);
        REQUIRE(sv.size() == 1);
        REQUIRE(sv[0] == 't');
    }
}

TEST_CASE("string_view: copy", "[string_view]")
{
    WHEN("offset = 0")
    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        REQUIRE(sv.copy(&buffer[0], 2, 0) == 2);
        REQUIRE(buffer[0] == 't');
        REQUIRE(buffer[1] == 'e');
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);
    }

    WHEN("offset = 1")
    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        REQUIRE(sv.copy(&buffer[0], 2, 1) == 2);
        REQUIRE(buffer[0] == 'e');
        REQUIRE(buffer[1] == 's');
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);
    }

    WHEN("offset = 3")
    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        REQUIRE(sv.copy(&buffer[0], 2, 3) == 1);
        REQUIRE(buffer[0] == 't');
        REQUIRE(buffer[1] == 0);
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);
    }
}

TEST_CASE("string_view: starts_with", "[string_view]")
{
    WHEN("rhs == string_view")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.starts_with("t"_sv));
        REQUIRE(sv.starts_with(etl::string_view { "te" }));
        REQUIRE(sv.starts_with(etl::string_view { "tes" }));
        REQUIRE(sv.starts_with("test"_sv));
    }

    WHEN("rhs == char")
    {
        auto const sv = "abc"_sv;
        REQUIRE(sv.starts_with('a'));
    }

    WHEN("rhs == char const*")
    {
        auto const sv = "abc"_sv;
        REQUIRE(sv.starts_with("a"));
        REQUIRE(sv.starts_with("ab"));
        REQUIRE(sv.starts_with("abc"));
    }
}

TEST_CASE("string_view: ends_with", "[string_view]")
{
    WHEN("rhs == string_view")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.ends_with("t"_sv));
        REQUIRE(sv.ends_with("st"_sv));
        REQUIRE(sv.ends_with("est"_sv));
        REQUIRE(sv.ends_with("test"_sv));
    }

    WHEN("rhs == char")
    {
        auto const sv = "abc"_sv;
        REQUIRE(sv.ends_with('c'));
        REQUIRE_FALSE(sv.ends_with('a'));
    }

    WHEN("rhs == char const*")
    {
        auto const sv = "abc"_sv;
        REQUIRE(sv.ends_with("c"));
        REQUIRE(sv.ends_with("bc"));
        REQUIRE(sv.ends_with("abc"));
    }
}

TEST_CASE("string_view: find", "[string_view]")
{
    WHEN("rhs == string_view")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find("t"_sv) == 0);
        REQUIRE(sv.find("est"_sv) == 1);

        REQUIRE(sv.find("st"_sv, 1) == 2);
        REQUIRE(sv.find("st"_sv, 2) == 2);
    }

    WHEN("rhs == char")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find('t') == 0);
        REQUIRE(sv.find('e') == 1);

        REQUIRE(sv.find('s') == 2);
        REQUIRE(sv.find('s', 2) == 2);
    }

    WHEN("rhs == const char* s, size_type pos, size_type count")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find("t", 0, 1) == 0);
        REQUIRE(sv.find("est", 0, 3) == 1);

        REQUIRE(sv.find("x", 0, 1) == etl::string_view::npos);
        REQUIRE(sv.find("foo", 0, 3) == etl::string_view::npos);
    }

    WHEN("rhs == const char* s, size_type pos")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find("t", 0) == 0);
        REQUIRE(sv.find("est", 0) == 1);

        REQUIRE(sv.find("x", 0) == etl::string_view::npos);
        REQUIRE(sv.find("foo", 0) == etl::string_view::npos);

        REQUIRE(sv.find("xxxxx", 0) == etl::string_view::npos);
        REQUIRE(sv.find("foobarbaz", 0) == etl::string_view::npos);
    }
}

// TEST_CASE("string_view: rfind", "[string_view]")
// {
//     // WHEN("rhs == string_view")
//     // {
//     //     auto const sv = "test"_sv;
//     //     REQUIRE(sv.rfind("t"_sv) == 3);
//     //     REQUIRE(sv.rfind("est"_sv) == 1);

//     //     REQUIRE(sv.rfind("st"_sv, 12) == 2);
//     //     REQUIRE(sv.rfind("st"_sv, 12) == 2);
//     // }

//     WHEN("rhs == char")
//     {
//         auto const sv = "test"_sv;
//         REQUIRE(sv.rfind('t') == 3);
//         REQUIRE(sv.rfind('e') == 1);

//         REQUIRE(sv.rfind('s') == 2);
//         REQUIRE(sv.rfind('s', 2) == 2);
//     }

//     WHEN("rhs == const char* s, size_type pos, size_type count")
//     {
//         auto const sv = "test"_sv;
//         REQUIRE(sv.rfind("t", etl::string_view::npos, 1) == 3);
//         REQUIRE(sv.rfind("est", etl::string_view::npos, 3) == 1);

//         REQUIRE(sv.rfind("x", etl::string_view::npos, 1) ==
//         etl::string_view::npos); REQUIRE(sv.rfind("foo",
//         etl::string_view::npos, 3) == etl::string_view::npos);
//     }

//     WHEN("rhs == const char* s, size_type pos")
//     {
//         auto const sv = "test"_sv;
//         REQUIRE(sv.rfind("t", etl::string_view::npos) == 3);
//         REQUIRE(sv.rfind("est", etl::string_view::npos) == 1);

//         REQUIRE(sv.rfind("x", 0) == etl::string_view::npos);
//         REQUIRE(sv.rfind("foo", 0) == etl::string_view::npos);

//         REQUIRE(sv.rfind("xxxxx", 0) == etl::string_view::npos);
//         REQUIRE(sv.rfind("foobarbaz", 0) == etl::string_view::npos);
//     }
// }

TEST_CASE("string_view: find_first_of", "[string_view]")
{
    WHEN("rhs == string_view")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_first_of("t"_sv) == 0);
        REQUIRE(sv.find_first_of("est"_sv) == 0);

        REQUIRE(sv.find_first_of("t"_sv, 1) == 3);
        REQUIRE(sv.find_first_of("st"_sv, 2) == 2);
    }

    WHEN("rhs == char")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_first_of('t') == 0);
        REQUIRE(sv.find_first_of('e') == 1);

        REQUIRE(sv.find_first_of('t', 1) == 3);
        REQUIRE(sv.find_first_of('s') == 2);
    }

    WHEN("rhs == const char* s, size_type pos, size_type count")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_first_of("t", 0, 1) == 0);
        REQUIRE(sv.find_first_of("est", 0, 3) == 0);

        REQUIRE(sv.find_first_of("x", 0, 1) == etl::string_view::npos);
        REQUIRE(sv.find_first_of("foo", 0, 3) == etl::string_view::npos);
    }

    WHEN("rhs == const char* s, size_type pos")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_first_of("t", 1) == 3);
        REQUIRE(sv.find_first_of("est", 1) == 1);

        REQUIRE(sv.find_first_of("x", 0) == etl::string_view::npos);
        REQUIRE(sv.find_first_of("foo", 0) == etl::string_view::npos);

        REQUIRE(sv.find_first_of("xxxxx", 0) == etl::string_view::npos);
        REQUIRE(sv.find_first_of("foobarbaz", 0) == etl::string_view::npos);
    }
}

TEST_CASE("string_view: find_first_not_of", "[string_view]")
{
    REQUIRE("BCDEF"_sv.find_first_not_of("ABC") == 2);
    REQUIRE("BCDEF"_sv.find_first_not_of("ABC", 4) == 4);
    REQUIRE("BCDEF"_sv.find_first_not_of('B') == 1);
    REQUIRE("BCDEF"_sv.find_first_not_of('D', 2) == 3);
}

TEST_CASE("string_view: find_last_of", "[string_view]")
{
    WHEN("rhs == string_view")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_of("t"_sv) == 3);
        REQUIRE(sv.find_last_of("est"_sv) == 3);

        REQUIRE(sv.find_last_of("t"_sv, 1) == 0);
        REQUIRE(sv.find_last_of("st"_sv, 2) == 2);
    }

    WHEN("rhs == char")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_of('t') == 3);
        REQUIRE(sv.find_last_of('e') == 1);
        REQUIRE(sv.find_last_of('s') == 2);
    }

    WHEN("rhs == const char* s, size_type pos, size_type count")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_of("t", 12, 1) == 3);
        REQUIRE(sv.find_last_of("es", 12, 2) == 2);

        REQUIRE(sv.find_last_of("x", 0, 1) == etl::string_view::npos);
        REQUIRE(sv.find_last_of("foo", 0, 3) == etl::string_view::npos);
    }

    WHEN("rhs == const char* s, size_type pos")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_of("t") == 3);
        REQUIRE(sv.find_last_of("es") == 2);

        REQUIRE(sv.find_last_of("x") == etl::string_view::npos);
        REQUIRE(sv.find_last_of("foo") == etl::string_view::npos);

        REQUIRE(sv.find_last_of("xxxxx") == etl::string_view::npos);
        REQUIRE(sv.find_last_of("foobarbaz") == etl::string_view::npos);
    }
}

TEST_CASE("string_view: find_last_not_of", "[string_view]")
{
    WHEN("rhs == string_view")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_not_of("t"_sv) == 2);
        REQUIRE(sv.find_last_not_of("est"_sv) == sv.npos);
        REQUIRE(sv.find_last_not_of(etl::string_view { "s" }, 2) == 1);
    }

    WHEN("rhs == char")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_not_of('t') == 2);
        REQUIRE(sv.find_last_not_of('e') == 3);
        REQUIRE(sv.find_last_not_of('s') == 3);
    }

    WHEN("rhs == const char* s, size_type pos, size_type count")
    {
        auto const npos = etl::string_view::npos;
        auto const sv   = "test"_sv;
        REQUIRE(sv.find_last_not_of("t", npos, 1) == 2);
        REQUIRE(sv.find_last_not_of("es", npos, 2) == 3);
        REQUIRE(sv.find_last_not_of("est", npos, 4) == npos);
        REQUIRE(sv.find_last_not_of("tes", npos, 4) == npos);
    }

    WHEN("rhs == const char* s, size_type pos")
    {
        auto const sv = "test"_sv;
        REQUIRE(sv.find_last_not_of("t") == 2);
        REQUIRE(sv.find_last_not_of("es") == 3);

        REQUIRE(sv.find_last_not_of("tes") == etl::string_view::npos);
        REQUIRE(sv.find_last_not_of("est") == etl::string_view::npos);
    }
}

TEST_CASE("string_view: substr", "[string_view]")
{
    auto const sv = "test"_sv;

    auto const sub1 = sv.substr(0, 1);
    REQUIRE(sub1.size() == 1);
    REQUIRE(sub1[0] == 't');

    auto const sub2 = sv.substr(0, 2);
    REQUIRE(sub2.size() == 2);
    REQUIRE(sub2[0] == 't');
    REQUIRE(sub2[1] == 'e');

    auto const sub3 = sv.substr(2, 2);
    REQUIRE(sub3.size() == 2);
    REQUIRE(sub3[0] == 's');
    REQUIRE(sub3[1] == 't');
}

TEST_CASE("string_view: compare(string)", "[string]")
{
    using namespace etl::literals;

    SECTION("empty string same capacity")
    {
        auto lhs = etl::string_view();
        auto rhs = etl::string_view();

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    SECTION("same size equal")
    {
        auto const lhs = "test"_sv;
        auto const rhs = "test"_sv;

        CHECK(lhs.compare("test") == 0);
        CHECK(lhs.compare("test"_sv) == 0);
        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);

        CHECK(lhs.compare(1, 1, "test") < 0);
        CHECK(lhs.compare(1, 1, "test"_sv) < 0);
        CHECK(lhs.compare(1, 1, rhs) < 0);
        CHECK(rhs.compare(1, 1, lhs) < 0);

        CHECK(lhs.compare(1, 1, rhs, 1, 1) == 0);
        CHECK(rhs.compare(1, 1, lhs, 1, 1) == 0);

        CHECK("te"_sv.compare(0, 2, "test"_sv, 0, 2) == 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 3) == 0);
        CHECK("abcabc"_sv.compare(3, 1, "abc"_sv, 0, 3) < 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 1) > 0);

        CHECK("abcabc"_sv.compare(3, 3, "abc", 3) == 0);
        CHECK("abcabc"_sv.compare(3, 1, "abc", 0, 3) < 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc", 0, 1) > 0);
    }

    SECTION("different size equal")
    {
        auto const lhs = "test"_sv;
        auto const rhs = "te"_sv;

        CHECK(lhs.compare(rhs) > 0);
        CHECK(rhs.compare("test"_sv) < 0);
    }
}

TEST_CASE("string_view: operator==", "[string_view]")
{
    auto [lhs, rhs, equal] = GENERATE(table<char const*, char const*, bool>({
        { "", "", true },
        { "a", "a", true },
        { "ab", "ab", true },
        { "abc", "abc", true },
        { "abcd", "abcd", true },
        { "abcde", "abcde", true },
        { "0000000000", "0000000000", true },
        { "abc", "foo", false },
        { "abcd", "foo", false },
        { "abcde", "foo", false },
    }));

    REQUIRE((etl::string_view { lhs } == etl::string_view { rhs }) == equal);
    REQUIRE((etl::string_view { rhs } == etl::string_view { lhs }) == equal);

    REQUIRE(
        (etl::string_view { lhs } == etl::static_string<16> { rhs }) == equal);
    REQUIRE(
        (etl::string_view { rhs } == etl::static_string<16> { lhs }) == equal);

    REQUIRE(
        (etl::static_string<16> { lhs } == etl::string_view { rhs }) == equal);
    REQUIRE(
        (etl::static_string<16> { rhs } == etl::string_view { lhs }) == equal);

    REQUIRE_FALSE(etl::string_view { lhs } == "test"_sv);
    REQUIRE_FALSE("test"_sv == etl::string_view { lhs });
}

TEST_CASE("string_view: operator!=", "[string_view]")
{
    auto [lhs, rhs, equal] = GENERATE(table<char const*, char const*, bool>({
        { "a", "a", false },
        { "ab", "ab", false },
        { "abc", "abc", false },
        { "abcd", "abcd", false },
        { "abcde", "abcde", false },
        { "0000000000", "0000000000", false },
        { "abc", "foo", true },
        { "abcd", "foo", true },
        { "abcde", "foo", true },
    }));

    REQUIRE((etl::string_view { lhs } != etl::string_view { rhs }) == equal);
    REQUIRE((etl::string_view { rhs } != etl::string_view { lhs }) == equal);

    REQUIRE(
        (etl::string_view { lhs } != etl::static_string<16> { rhs }) == equal);
    REQUIRE(
        (etl::string_view { rhs } != etl::static_string<16> { lhs }) == equal);

    REQUIRE(
        (etl::static_string<16> { lhs } != etl::string_view { rhs }) == equal);
    REQUIRE(
        (etl::static_string<16> { rhs } != etl::string_view { lhs }) == equal);

    REQUIRE(etl::string_view { lhs } != "test"_sv);
    REQUIRE("test"_sv != etl::string_view { lhs });
}

TEST_CASE("string_view: operator<", "[string_view]")
{
    auto const sv  = "test"_sv;
    auto const str = etl::static_string<16> { "test" };
    REQUIRE_FALSE(sv < sv);
    REQUIRE(etl::string_view { "" } < sv);
    REQUIRE(sv.substr(0, 1) < sv);
    REQUIRE("abc"_sv < sv);
    REQUIRE_FALSE(sv < str);
    REQUIRE_FALSE(str < sv);
}

TEST_CASE("string_view: operator<=", "[string_view]")
{
    auto const sv = "test"_sv;
    REQUIRE(sv <= sv);
    REQUIRE(etl::string_view { "" } <= sv);
    REQUIRE(sv.substr(0, 1) <= sv);
    REQUIRE("abc"_sv <= sv);
}

TEST_CASE("string_view: operator>", "[string_view]")
{
    auto const sv = "test"_sv;
    REQUIRE_FALSE(sv > sv);
    REQUIRE(etl::string_view { "xxxxxx" } > sv);
    REQUIRE(sv > sv.substr(0, 1));
    REQUIRE(sv > "abc"_sv);
}

TEST_CASE("string_view: operator>=", "[string_view]")
{
    auto const sv = "test"_sv;
    REQUIRE(sv >= sv);
    REQUIRE(etl::string_view { "xxxxxx" } >= sv);
    REQUIRE(sv >= sv.substr(0, 1));
    REQUIRE(sv >= "abc"_sv);
}

TEST_CASE("string_view: operator\"\"", "[string_view]")
{
    auto const sv = "test"_sv;
    REQUIRE(sv.size() >= 4);
    REQUIRE(sv[0] >= 't');
}
