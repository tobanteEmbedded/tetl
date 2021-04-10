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
#include "catch2/generators/catch_generators.hpp"

#include "etl/format.hpp"

TEMPLATE_TEST_CASE("format: formatter<char>", "[format]",
                   etl::static_string<12>, etl::static_string<32>)
{
  using string_t = TestType;

  auto str       = string_t();
  auto ctx       = etl::format_context<string_t> {etl::back_inserter(str)};
  auto formatter = etl::formatter<char, char> {};

  formatter.format('a', ctx);
  CHECK(str[0] == 'a');

  formatter.format('x', ctx);
  CHECK(str[1] == 'x');

  formatter.format('1', ctx);
  CHECK(str[2] == '1');
}

TEMPLATE_TEST_CASE("format: formatter<char[N]>", "[format]",
                   etl::static_string<12>, etl::static_string<32>)
{
  using string_t = TestType;

  auto str = string_t();
  auto ctx = etl::format_context<string_t> {etl::back_inserter(str)};

  auto f1 = etl::formatter<char[sizeof("abc")], char> {};
  f1.format("abc", ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view("abc"));

  str.clear();
  auto f2 = etl::formatter<char[sizeof("foobar")], char> {};
  f2.format("foobar", ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view("foobar"));
}

TEMPLATE_TEST_CASE("format: formatter<char const*>", "[format]",
                   etl::static_string<12>, etl::static_string<32>)
{
  using string_t = TestType;

  auto str       = string_t();
  auto ctx       = etl::format_context<string_t> {etl::back_inserter(str)};
  auto formatter = etl::formatter<char const*, char> {};

  auto const* cStr1 = "test";
  formatter.format(cStr1, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(cStr1));

  str.clear();
  auto const* cStr2 = "abcdef";
  formatter.format(cStr2, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(cStr2));
}

TEMPLATE_TEST_CASE("format: formatter<string_view>", "[format]",
                   etl::static_string<12>, etl::static_string<32>)
{
  using string_t = TestType;

  auto str       = string_t();
  auto ctx       = etl::format_context<string_t> {etl::back_inserter(str)};
  auto formatter = etl::formatter<etl::string_view, char> {};

  etl::string_view str1 = "test";
  formatter.format(str1, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str1));

  str.clear();
  etl::string_view str2 = "abcdef";
  formatter.format(str2, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str2));
}

TEMPLATE_TEST_CASE("format: formatter<static_string<Capacity>>", "[format]",
                   etl::static_string<12>, etl::static_string<32>)
{
  using string_t = TestType;

  auto str       = string_t();
  auto ctx       = etl::format_context<string_t> {etl::back_inserter(str)};
  auto formatter = etl::formatter<string_t, char> {};

  string_t str1 = "test";
  formatter.format(str1, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str1));

  str.clear();
  string_t str2 = "abcdef";
  formatter.format(str2, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str2));
}

TEMPLATE_TEST_CASE("format: formatter<Integer>", "[format]", short, int, long,
                   long long, unsigned short, unsigned int, unsigned long,
                   unsigned long long)
{
  auto [test_input, expected]
    = GENERATE(Catch::Generators::table<TestType, char const*>({
      {0, "0"},
      {1, "1"},
      {2, "2"},
      {3, "3"},
      {4, "4"},
      {5, "5"},
      {6, "6"},
      {7, "7"},
      {8, "8"},
      {9, "9"},
      {10, "10"},
      {11, "11"},
      {99, "99"},
      {111, "111"},
      {1234, "1234"},
      {9999, "9999"},
    }));

  using string_t = etl::static_string<32>;

  auto str       = string_t();
  auto ctx       = etl::format_context<string_t> {etl::back_inserter(str)};
  auto formatter = etl::formatter<TestType, char> {};

  formatter.format(test_input, ctx);
  CHECK(str == expected);
}

TEST_CASE("format: format_to<char>", "[format]")
{
  SECTION("no arg")
  {
    auto str    = etl::static_string<32> {};
    auto target = etl::string_view("test");
    etl::format_to(etl::back_inserter(str), "test");
    CHECK(etl::string_view(str) == target);
  }

  SECTION("no arg escaped")
  {
    auto str1 = etl::static_string<32> {};
    etl::format_to(etl::back_inserter(str1), "{{test}}");
    CHECK(etl::string_view(str1) == etl::string_view("{test}"));

    auto str2 = etl::static_string<32> {};
    etl::format_to(etl::back_inserter(str2), "{{abc}} {{def}}");
    CHECK(etl::string_view(str2) == etl::string_view("{abc} {def}"));
  }

  SECTION("single arg")
  {
    auto str    = etl::static_string<32> {};
    auto target = etl::string_view("test");
    etl::format_to(etl::back_inserter(str), "tes{}", 't');
    CHECK(etl::string_view(str) == target);
  }

  SECTION("escape single arg")
  {
    auto str1 = etl::static_string<32> {};
    etl::format_to(etl::back_inserter(str1), "{} {{test}}", 'a');
    CHECK(etl::string_view(str1) == etl::string_view("a {test}"));

    // auto str_2 = etl::static_string<32> {};
    // etl::format_to(etl::back_inserter(str_2), "{{test}} {}", 'b');
    // CHECK(etl::string_view(str_2.data()) == etl::string_view("{test} b"));
  }

  SECTION("replace multiple args")
  {
    auto str1 = etl::static_string<32> {};
    etl::format_to(etl::back_inserter(str1), "{} {} {}", 'a', 'b', 'c');
    CHECK(etl::string_view(str1) == etl::string_view("a b c"));

    auto str2 = etl::static_string<32> {};
    auto fmt2 = etl::string_view("some {} text {} mixed {}");
    etl::format_to(etl::back_inserter(str2), fmt2, 'a', 'b', 'c');
    CHECK(etl::string_view(str2) == etl::string_view("some a text b mixed c"));
  }
}

TEST_CASE("format: format_to<char[N]>", "[format]")
{
  SECTION("single arg")
  {
    auto str    = etl::static_string<32> {};
    auto target = etl::string_view("testtt");
    etl::format_to(etl::back_inserter(str), "tes{}", "ttt");
    CHECK(etl::string_view(str.begin()) == target);
  }

  SECTION("escape single arg")
  {
    // auto str_1 = etl::static_string<32> {};
    // etl::format_to(etl::back_inserter(str_1), "{} {{test}}", "abc");
    // CHECK(etl::string_view(str_1.begin()) == etl::string_view("abc {test}"));

    //     auto str_2 = etl::static_string<32> {};
    //     etl::format_to(etl::back_inserter(str_2), "{{test}} {}", "abc");
    //     CHECK(etl::string_view(str_2.begin()) == etl::string_view("{test}
    //     abc"));
  }

  //     SECTION("replace multiple args")
  //     {
  //         //        auto str_1 = etl::static_string<32> {};
  //         //        etl::format_to(etl::back_inserter(str_1), "{} {} {}",
  //         "abc", "def",
  //         //        "ghi"); CHECK(etl::string_view(str_1.begin()) ==
  //         etl::string_view("abc
  //         //        def ghi"));

  //         //     auto str_2 = etl::static_string<32> {};
  //         //     auto fmt_2 = etl::string_view("some {} text {} mixed {}");
  //         //     etl::format_to(etl::back_inserter(str_2), fmt_2, "abc",
  //         "def", "ghi");
  //         //     CHECK(etl::string_view(str_2) == etl::string_view("some abc
  //         text def mixed
  //         //     ghi"));
  //     }
}

TEST_CASE("format: format_to_n", "[format]")
{
  SECTION("escape")
  {
    auto buffer = etl::static_string<32> {};
    auto target = etl::string_view("{abc}");
    auto res
      = etl::format_to_n(buffer.data(), (ptrdiff_t)buffer.size(), "{{abc}}");
    CHECK(res.out == buffer.begin() + target.size());
    CHECK(res.size == static_cast<decltype(res.size)>(target.size()));
    CHECK(etl::string_view(buffer.begin()) == target);
  }

  SECTION("replace single arg")
  {
    auto buffer = etl::static_string<32> {};
    auto target = etl::string_view("test");
    auto res
      = etl::format_to_n(data(buffer), (ptrdiff_t)buffer.size(), "tes{}", 't');
    CHECK(res.out == buffer.begin() + target.size());
    CHECK(res.size == static_cast<decltype(res.size)>(target.size()));
    CHECK(etl::string_view(buffer.begin()) == target);
  }

  // SECTION("replace multiple args")
  // {
  //     auto buffer  = etl::static_string<32> {};
  //     auto fmt_str = etl::string_view("{} {}");
  //     auto target  = etl::string_view("a b");
  //     auto res     = etl::format_to_n(buffer.data(), buffer.size(),
  //     fmt_str, 'a', 'b'); CHECK(res.out == buffer.begin() + target.size());
  //     CHECK(res.size == static_cast<decltype(res.size)>(target.size()));
  //     CHECK(etl::string_view(buffer.begin()) == target);
  // }
}

TEST_CASE("format: detail::split_at_next_argument", "[format]")
{
  using namespace etl::literals;

  SECTION("argument only")
  {
    auto slices = etl::detail::split_at_next_argument("{}");
    CHECK(slices.first == ""_sv);
    CHECK(slices.second == ""_sv);
  }

  SECTION("prefix")
  {
    auto slices = etl::detail::split_at_next_argument("a{}");
    CHECK(slices.first == "a"_sv);
    CHECK(slices.second == ""_sv);
  }

  SECTION("postfix")
  {
    auto slices = etl::detail::split_at_next_argument("{}b");
    CHECK(slices.first == ""_sv);
    CHECK(slices.second == "b"_sv);
  }

  SECTION("pre&postfix")
  {
    auto slices = etl::detail::split_at_next_argument("ab{}cd");
    CHECK(slices.first == "ab"_sv);
    CHECK(slices.second == "cd"_sv);
  }

  SECTION("escape")
  {
    auto slices = etl::detail::split_at_next_argument("{{test}}");
    CHECK(slices.first == "{{test}}"_sv);
    CHECK(slices.second == ""_sv);
  }
}

TEST_CASE("format: detail::format_escaped_sequences", "[format]")
{
  using namespace etl::literals;

  using string_t = etl::static_string<32>;

  SECTION("none")
  {
    auto str = string_t {};
    auto ctx = etl::format_context<string_t> {etl::back_inserter(str)};
    etl::detail::format_escaped_sequences("test", ctx);
    CHECK(etl::string_view(str) == "test"_sv);
  }

  SECTION("single")
  {
    auto str = string_t {};
    auto ctx = etl::format_context<string_t> {etl::back_inserter(str)};
    etl::detail::format_escaped_sequences("{{test}}", ctx);
    CHECK(etl::string_view(str) == "{test}"_sv);
  }

  SECTION("single with noise")
  {
    auto str1 = string_t {};
    auto ctx1 = etl::format_context<string_t> {etl::back_inserter(str1)};
    etl::detail::format_escaped_sequences("foobar {{test}}", ctx1);
    CHECK(etl::string_view(str1) == "foobar {test}"_sv);

    auto str2 = string_t {};
    auto ctx2 = etl::format_context<string_t> {etl::back_inserter(str2)};
    etl::detail::format_escaped_sequences("foobar__{{test}}", ctx2);
    CHECK(etl::string_view(str2) == "foobar__{test}"_sv);

    auto str3 = string_t {};
    auto ctx3 = etl::format_context<string_t> {etl::back_inserter(str3)};
    etl::detail::format_escaped_sequences("{{test}} foobar", ctx3);
    CHECK(etl::string_view(str3) == "{test} foobar"_sv);

    auto str4 = string_t {};
    auto ctx4 = etl::format_context<string_t> {etl::back_inserter(str4)};
    etl::detail::format_escaped_sequences("{{test}}__foobar", ctx4);
    CHECK(etl::string_view(str4) == "{test}__foobar"_sv);
  }

  SECTION("multiple")
  {
    auto str1 = string_t {};
    auto ctx1 = etl::format_context<string_t> {etl::back_inserter(str1)};
    etl::detail::format_escaped_sequences("{{test}} {{abc}}", ctx1);
    CHECK(etl::string_view(str1) == "{test} {abc}"_sv);

    auto str2 = string_t {};
    auto ctx2 = etl::format_context<string_t> {etl::back_inserter(str2)};
    etl::detail::format_escaped_sequences("{{test}}{{abc}}", ctx2);
    CHECK(etl::string_view(str2) == "{test}{abc}"_sv);
  }
}
