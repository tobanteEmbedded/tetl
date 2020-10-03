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

TEMPLATE_TEST_CASE("experimental/format: formatter<char>", "[experimental][format]",
                   etl::static_string<12>, etl::static_string<32>)
{
    namespace fmt  = etl::experimental::format;
    using string_t = TestType;

    auto str       = string_t();
    auto ctx       = fmt::format_context<string_t> {etl::back_inserter(str)};
    auto formatter = fmt::formatter<char, char> {};

    formatter.format('a', ctx);
    CHECK(str[0] == 'a');

    formatter.format('x', ctx);
    CHECK(str[1] == 'x');

    formatter.format('1', ctx);
    CHECK(str[2] == '1');
}

TEMPLATE_TEST_CASE("experimental/format: formatter<char[N]>", "[experimental][format]",
                   etl::static_string<12>, etl::static_string<32>)
{
    namespace fmt  = etl::experimental::format;
    using string_t = TestType;

    auto str = string_t();
    auto ctx = fmt::format_context<string_t> {etl::back_inserter(str)};

    auto f1 = fmt::formatter<char[sizeof("abc")], char> {};
    f1.format("abc", ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view("abc"));

    str.clear();
    auto f2 = fmt::formatter<char[sizeof("foobar")], char> {};
    f2.format("foobar", ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view("foobar"));
}

TEMPLATE_TEST_CASE("experimental/format: formatter<char const*>",
                   "[experimental][format]", etl::static_string<12>,
                   etl::static_string<32>)
{
    namespace fmt  = etl::experimental::format;
    using string_t = TestType;

    auto str       = string_t();
    auto ctx       = fmt::format_context<string_t> {etl::back_inserter(str)};
    auto formatter = fmt::formatter<char const*, char> {};

    auto* c_str_1 = "test";
    formatter.format(c_str_1, ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view(c_str_1));

    str.clear();
    auto* c_str_2 = "abcdef";
    formatter.format(c_str_2, ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view(c_str_2));
}

TEMPLATE_TEST_CASE("experimental/format: formatter<string_view>",
                   "[experimental][format]", etl::static_string<12>,
                   etl::static_string<32>)
{
    namespace fmt  = etl::experimental::format;
    using string_t = TestType;

    auto str       = string_t();
    auto ctx       = fmt::format_context<string_t> {etl::back_inserter(str)};
    auto formatter = fmt::formatter<etl::string_view, char> {};

    etl::string_view str_1 = "test";
    formatter.format(str_1, ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view(str_1));

    str.clear();
    etl::string_view str_2 = "abcdef";
    formatter.format(str_2, ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view(str_2));
}

TEMPLATE_TEST_CASE("experimental/format: formatter<static_string<Capacity>>",
                   "[experimental][format]", etl::static_string<12>,
                   etl::static_string<32>)
{
    namespace fmt  = etl::experimental::format;
    using string_t = TestType;

    auto str       = string_t();
    auto ctx       = fmt::format_context<string_t> {etl::back_inserter(str)};
    auto formatter = fmt::formatter<string_t, char> {};

    string_t str_1 = "test";
    formatter.format(str_1, ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view(str_1));

    str.clear();
    string_t str_2 = "abcdef";
    formatter.format(str_2, ctx);
    CHECK(etl::string_view(str.data()) == etl::string_view(str_2));
}

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

        // auto str_2 = etl::static_string<32> {};
        // fmt::format_to(etl::back_inserter(str_2), "{{test}} {}", 'b');
        // CHECK(std::string_view(str_2.data()) == std::string_view("{test} b"));
    }

    SECTION("replace multiple args")
    {
        auto str_1 = etl::static_string<32> {};
        fmt::format_to(etl::back_inserter(str_1), "{} {} {}", 'a', 'b', 'c');
        CHECK(etl::string_view(str_1) == etl::string_view("a b c"));

        auto str_2 = etl::static_string<32> {};
        auto fmt_2 = etl::string_view("some {} text {} mixed {}");
        fmt::format_to(etl::back_inserter(str_2), fmt_2, 'a', 'b', 'c');
        CHECK(etl::string_view(str_2) == etl::string_view("some a text b mixed c"));
    }
}

TEST_CASE("experimental/format: format_to<char[N]>", "[experimental][format]")
{
    namespace fmt = etl::experimental::format;

    SECTION("single arg")
    {
        auto str    = etl::static_string<32> {};
        auto target = etl::string_view("testtt");
        fmt::format_to(etl::back_inserter(str), "tes{}", "ttt");
        CHECK(etl::string_view(str.begin()) == target);
    }

    SECTION("escape single arg")
    {
        // auto str_1 = etl::static_string<32> {};
        // fmt::format_to(etl::back_inserter(str_1), "{} {{test}}", "abc");
        // CHECK(std::string_view(str_1.begin()) == std::string_view("abc {test}"));

        //     auto str_2 = etl::static_string<32> {};
        //     fmt::format_to(etl::back_inserter(str_2), "{{test}} {}", "abc");
        //     CHECK(std::string_view(str_2.begin()) == std::string_view("{test} abc"));
    }

    //     SECTION("replace multiple args")
    //     {
    //         //        auto str_1 = etl::static_string<32> {};
    //         //        fmt::format_to(etl::back_inserter(str_1), "{} {} {}", "abc",
    //         "def",
    //         //        "ghi"); CHECK(std::string_view(str_1.begin()) ==
    //         std::string_view("abc
    //         //        def ghi"));

    //         //     auto str_2 = etl::static_string<32> {};
    //         //     auto fmt_2 = etl::string_view("some {} text {} mixed {}");
    //         //     fmt::format_to(etl::back_inserter(str_2), fmt_2, "abc", "def",
    //         "ghi");
    //         //     CHECK(etl::string_view(str_2) == etl::string_view("some abc text def
    //         mixed
    //         //     ghi"));
    //     }
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

TEST_CASE("experimental/format: detail::slice_next_argument", "[experimental][format]")
{
    namespace fmt = etl::experimental::format;
    using namespace etl::literals;

    SECTION("argument only")
    {
        auto slices = fmt::detail::slice_next_argument("{}");
        CHECK(slices.first == ""_sv);
        CHECK(slices.second == ""_sv);
    }

    SECTION("prefix")
    {
        auto slices = fmt::detail::slice_next_argument("a{}");
        CHECK(slices.first == "a"_sv);
        CHECK(slices.second == ""_sv);
    }

    SECTION("postfix")
    {
        auto slices = fmt::detail::slice_next_argument("{}b");
        CHECK(slices.first == ""_sv);
        CHECK(slices.second == "b"_sv);
    }

    SECTION("pre&postfix")
    {
        auto slices = fmt::detail::slice_next_argument("ab{}cd");
        CHECK(slices.first == "ab"_sv);
        CHECK(slices.second == "cd"_sv);
    }

    SECTION("escape")
    {
        auto slices = fmt::detail::slice_next_argument("{{test}}");
        CHECK(slices.first == "{{test}}"_sv);
        CHECK(slices.second == ""_sv);
    }
}

TEST_CASE("experimental/format: detail::format_escaped_sequences",
          "[experimental][format]")
{
    namespace fmt = etl::experimental::format;
    using namespace etl::literals;
    using namespace std::literals;

    using string_t = etl::static_string<32>;

    SECTION("none")
    {
        auto str = string_t {};
        auto ctx = fmt::format_context<string_t> {etl::back_inserter(str)};
        fmt::detail::format_escaped_sequences(ctx, "test");
        CHECK(etl::string_view(str) == "test"_sv);
    }

    SECTION("single")
    {
        auto str = string_t {};
        auto ctx = fmt::format_context<string_t> {etl::back_inserter(str)};
        fmt::detail::format_escaped_sequences(ctx, "{{test}}");
        CHECK(etl::string_view(str) == "{test}"_sv);
    }

    SECTION("single with noise")
    {
        auto str_1 = string_t {};
        auto ctx_1 = fmt::format_context<string_t> {etl::back_inserter(str_1)};
        fmt::detail::format_escaped_sequences(ctx_1, "foobar {{test}}");
        CHECK(etl::string_view(str_1) == "foobar {test}"_sv);

        auto str_2 = string_t {};
        auto ctx_2 = fmt::format_context<string_t> {etl::back_inserter(str_2)};
        fmt::detail::format_escaped_sequences(ctx_2, "foobar__{{test}}");
        CHECK(etl::string_view(str_2) == "foobar__{test}"_sv);

        auto str_3 = string_t {};
        auto ctx_3 = fmt::format_context<string_t> {etl::back_inserter(str_3)};
        fmt::detail::format_escaped_sequences(ctx_3, "{{test}} foobar");
        CHECK(etl::string_view(str_3) == "{test} foobar"_sv);

        auto str_4 = string_t {};
        auto ctx_4 = fmt::format_context<string_t> {etl::back_inserter(str_4)};
        fmt::detail::format_escaped_sequences(ctx_4, "{{test}}__foobar");
        CHECK(etl::string_view(str_4) == "{test}__foobar"_sv);
    }

    SECTION("multiple")
    {
        auto str_1 = string_t {};
        auto ctx_1 = fmt::format_context<string_t> {etl::back_inserter(str_1)};
        fmt::detail::format_escaped_sequences(ctx_1, "{{test}} {{abc}}");
        CHECK(etl::string_view(str_1) == "{test} {abc}"_sv);

        auto str_2 = string_t {};
        auto ctx_2 = fmt::format_context<string_t> {etl::back_inserter(str_2)};
        fmt::detail::format_escaped_sequences(ctx_2, "{{test}}{{abc}}");
        CHECK(etl::string_view(str_2) == "{test}{abc}"_sv);
    }
}
