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

#include "catch2/catch_template_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

TEMPLATE_TEST_CASE("experimental/format: formatter<char>",
                   "[experimental][format]", etl::static_string<12>,
                   etl::static_string<32>)
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

TEMPLATE_TEST_CASE("experimental/format: formatter<char[N]>",
                   "[experimental][format]", etl::static_string<12>,
                   etl::static_string<32>)
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

  auto const* cStr1 = "test";
  formatter.format(cStr1, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(cStr1));

  str.clear();
  auto const* cStr2 = "abcdef";
  formatter.format(cStr2, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(cStr2));
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

  etl::string_view str1 = "test";
  formatter.format(str1, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str1));

  str.clear();
  etl::string_view str2 = "abcdef";
  formatter.format(str2, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str2));
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

  string_t str1 = "test";
  formatter.format(str1, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str1));

  str.clear();
  string_t str2 = "abcdef";
  formatter.format(str2, ctx);
  CHECK(etl::string_view(str.data()) == etl::string_view(str2));
}

TEMPLATE_TEST_CASE("experimental/format: formatter<Integer>",
                   "[experimental][format]", short, int, long, long long,
                   unsigned short, unsigned int, unsigned long,
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

  namespace fmt  = etl::experimental::format;
  using string_t = etl::static_string<32>;

  auto str       = string_t();
  auto ctx       = fmt::format_context<string_t> {etl::back_inserter(str)};
  auto formatter = fmt::formatter<TestType, char> {};

  formatter.format(test_input, ctx);
  CHECK(str == expected);
}