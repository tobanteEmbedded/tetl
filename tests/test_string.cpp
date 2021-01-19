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

#include "catch2/catch.hpp"

#include "etl/algorithm.hpp"  // for for_each
#include "etl/cstddef.hpp"    // for size_t
#include "etl/string.hpp"     // for static_string

TEST_CASE("string/char_traits: <char>::length", "[string]")
{
  STATIC_REQUIRE(etl::char_traits<char>::length("") == 0);
  STATIC_REQUIRE(etl::char_traits<char>::length("a") == 1);
  STATIC_REQUIRE(etl::char_traits<char>::length("to") == 2);
  STATIC_REQUIRE(etl::char_traits<char>::length("xxxxxxxxxx") == 10);
}

TEST_CASE("string/char_traits: <char>::eq", "[string]")
{
  STATIC_REQUIRE(etl::char_traits<char>::eq('a', 'a') == true);
  STATIC_REQUIRE(etl::char_traits<char>::eq('a', 'b') == false);
  STATIC_REQUIRE(etl::char_traits<char>::eq('b', 'a') == false);
}

TEST_CASE("string/char_traits: <char>::lt", "[string]")
{
  STATIC_REQUIRE(etl::char_traits<char>::lt('a', 'a') == false);
  STATIC_REQUIRE(etl::char_traits<char>::lt('a', 'b') == true);
  STATIC_REQUIRE(etl::char_traits<char>::lt('b', 'a') == false);
}

TEST_CASE("string/char_traits: <char>::assign(char,char)", "[string]")
{
  auto ch = [](char const& b) {
    auto a = 'a';
    etl::char_traits<char>::assign(a, b);
    return a;
  };

  STATIC_REQUIRE(ch('b') == 'b');
}

TEMPLATE_TEST_CASE("string: ctor()", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
  TestType str {};

  CHECK_FALSE(str.full());
  CHECK(str.empty());
  CHECK(str.capacity() == str.max_size());
  CHECK(str.size() == etl::size_t(0));
  CHECK(str.length() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: ctor(size_t,char)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  auto str = TestType(10, 'a');
  CHECK_FALSE(str.empty());
  CHECK_FALSE(str.full());
  CHECK(str.size() == etl::size_t(10));
  CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
}

TEMPLATE_TEST_CASE("string: ctor(char const*)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  TestType str {"abc"};

  CHECK_FALSE(str.full());
  CHECK_FALSE(str.empty());
  CHECK(str.capacity() == str.max_size());
  CHECK(etl::strlen(str.data()) == etl::size_t(3));
  CHECK(str.size() == etl::size_t(3));
  CHECK(str.length() == etl::size_t(3));
  CHECK(str[0] == 'a');
  CHECK(str[1] == 'b');
  CHECK(str[2] == 'c');
}

TEMPLATE_TEST_CASE("string: ctor(char const*, size_t)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  auto const* src = "abc";
  TestType str {src, etl::strlen(src)};

  CHECK_FALSE(str.full());
  CHECK_FALSE(str.empty());
  CHECK(etl::strlen(str.data()) == etl::size_t(3));
  CHECK(str.capacity() == str.max_size());
  CHECK(str.size() == etl::size_t(3));
  CHECK(str.length() == etl::size_t(3));
  CHECK(str[0] == 'a');
  CHECK(str[1] == 'b');
  CHECK(str[2] == 'c');
}

TEMPLATE_TEST_CASE("string: ctor(first,last)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  TestType src {"test"};
  TestType dest {begin(src), end(src)};

  CHECK_FALSE(dest.full());
  CHECK(etl::strlen(dest.data()) == etl::size_t(4));
  CHECK(dest.size() == etl::size_t(4));
  CHECK(dest.length() == etl::size_t(4));
  CHECK(dest[0] == 't');
  CHECK(dest[1] == 'e');
  CHECK(dest[2] == 's');
  CHECK(dest[3] == 't');
}

TEMPLATE_TEST_CASE("string: ctor(string,pos)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  TestType src {"testabc"};

  TestType dest_1(src, 0);
  CHECK(etl::string_view(dest_1) == etl::string_view(src));

  TestType dest_2(src, 4);
  CHECK(etl::string_view(dest_2) == etl::string_view("abc"));

  auto dest_3 = TestType(src, 9);
  CHECK(etl::string_view(dest_3) == etl::string_view(""));
}

TEMPLATE_TEST_CASE("string: ctor(string,pos,count)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  TestType src {"testabc"};

  TestType dest_1(src, 0, 2);
  CHECK(etl::string_view(dest_1) == etl::string_view("te"));

  TestType dest_2(src, 4, 2);
  CHECK(etl::string_view(dest_2) == etl::string_view("ab"));

  auto dest_3 = TestType(src, 9, 2);
  CHECK(etl::string_view(dest_3) == etl::string_view(""));
}

TEMPLATE_TEST_CASE("string: ctor(string_view)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  etl::string_view sv {"test"};
  TestType dest {sv};

  CHECK_FALSE(dest.full());
  CHECK(dest.size() == etl::size_t(4));
  CHECK(dest.length() == etl::size_t(4));
  CHECK(dest[0] == 't');
  CHECK(dest[1] == 'e');
  CHECK(dest[2] == 's');
  CHECK(dest[3] == 't');
}

TEMPLATE_TEST_CASE("string: ctor(string_view,pos,n)", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
  etl::string_view sv {"test"};
  TestType dest {sv, 2, 2};

  CHECK_FALSE(dest.full());
  CHECK(dest.size() == etl::size_t(2));
  CHECK(dest.length() == etl::size_t(2));
  CHECK(dest[0] == 's');
  CHECK(dest[1] == 't');
}

TEMPLATE_TEST_CASE("string: operator=", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("string")
  {
    TestType src_1 {};
    TestType str_1 {};
    str_1 = src_1;
    CHECK(str_1.size() == 0);
    CHECK(str_1.empty());

    TestType src_2 {"test"};
    TestType str_2 {};
    str_2 = src_2;
    CHECK(str_2.size() == 4);
    CHECK(etl::string_view(str_2) == etl::string_view("test"));

    auto src_3 = TestType {"abc"};
    TestType str_3;
    str_3 = src_3;
    CHECK(str_3.size() == 3);
    CHECK(etl::string_view(str_3) == etl::string_view("abc"));
  }

  SECTION("char const*")
  {
    auto const* src_2 = "test";
    TestType str_2 {};
    str_2 = src_2;
    CHECK(str_2.size() == 4);
    CHECK(etl::string_view(str_2) == etl::string_view("test"));

    auto const* src_3 = "abc";
    TestType str_3;
    str_3 = src_3;
    CHECK(str_3.size() == 3);
    CHECK(etl::string_view(str_3) == etl::string_view("abc"));
  }

  SECTION("char")
  {
    auto const src_2 = 'a';
    TestType str_2 {};
    str_2 = src_2;
    CHECK(str_2.size() == 1);
    CHECK(etl::string_view(str_2) == etl::string_view("a"));

    auto const src_3 = 'b';
    TestType str_3;
    str_3 = src_3;
    CHECK(str_3.size() == 1);
    CHECK(etl::string_view(str_3) == etl::string_view("b"));
  }

  SECTION("string_view")
  {
    etl::string_view src_1 {};
    TestType str_1 {};
    str_1 = src_1;
    CHECK(str_1.size() == 0);

    etl::string_view src_2 {"test"};
    TestType str_2 {};
    str_2 = src_2;
    CHECK(str_2.size() == 4);
    CHECK(etl::string_view(str_2) == etl::string_view("test"));

    auto src_3 = etl::string_view {"abc"};
    TestType str_3;
    str_3 = src_3;
    CHECK(str_3.size() == 3);
    CHECK(etl::string_view(str_3) == etl::string_view("abc"));
  }
}

TEMPLATE_TEST_CASE("string: assign", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("string")
  {
    TestType dest {};

    auto const src_1 = TestType {};
    dest.assign(src_1);
    CHECK(dest.size() == 0);
    CHECK(dest.empty());

    auto const src_2 = TestType {"test"};
    dest.assign(src_2);
    CHECK(dest.size() == 4);
    CHECK(etl::string_view(dest) == etl::string_view("test"));

    auto src_3 = TestType {"abc"};
    dest.assign(etl::move(src_3));
    CHECK(dest.size() == 3);
    CHECK(etl::string_view(dest) == etl::string_view("abc"));

    auto const src_4 = TestType {"abc"};
    dest.assign(src_4, 1, 1);
    CHECK(dest.size() == 1);
    CHECK(etl::string_view(dest) == etl::string_view("b"));
  }

  SECTION("string_view")
  {
    TestType dest {};

    dest.assign(etl::string_view {});
    CHECK(dest.size() == 0);
    CHECK(dest.empty());

    dest.assign(etl::string_view {"test"});
    CHECK(dest.size() == 4);
    CHECK(etl::string_view(dest) == etl::string_view("test"));

    dest.assign(etl::string_view {"abc"});
    CHECK(dest.size() == 3);
    CHECK(etl::string_view(dest) == etl::string_view("abc"));

    dest.assign(etl::string_view {"abc"}, 0);
    CHECK(dest.size() == 3);
    CHECK(etl::string_view(dest) == etl::string_view("abc"));

    dest.assign(etl::string_view {"abc"}, 1);
    CHECK(dest.size() == 2);
    CHECK(etl::string_view(dest) == etl::string_view("bc"));

    dest.assign(etl::string_view {"abc"}, 1, 1);
    CHECK(dest.size() == 1);
    CHECK(etl::string_view(dest) == etl::string_view("b"));

    auto const src = etl::static_string<8> {"abc"};
    dest.assign(src);
    CHECK(dest.size() == 3);
    CHECK(etl::string_view(dest) == etl::string_view("abc"));

    dest.assign(src, 1, 1);
    CHECK(dest.size() == 1);
    CHECK(etl::string_view(dest) == etl::string_view("b"));
  }

  SECTION("first, last")
  {
    TestType dest {};

    auto src_1 = etl::string_view("test");
    dest.assign(begin(src_1), end(src_1));
    CHECK(dest.size() == 4);
    CHECK(etl::string_view(dest) == etl::string_view("test"));

    auto src_2 = etl::string_view("abc");
    dest.assign(begin(src_2), end(src_2) - 1);
    CHECK(dest.size() == 2);
    CHECK(etl::string_view(dest) == etl::string_view("ab"));
  }

  SECTION("char const*")
  {
    TestType dest {};

    dest.assign("test");
    CHECK(dest.size() == 4);
    CHECK(etl::string_view(dest) == etl::string_view("test"));

    dest.assign("abc");
    CHECK(dest.size() == 3);
    CHECK(etl::string_view(dest) == etl::string_view("abc"));
  }

  SECTION("char")
  {
    TestType dest {};

    dest.assign(1, 'a');
    CHECK(dest.size() == 1);
    CHECK(etl::string_view(dest) == etl::string_view("a"));

    dest.assign(4, 'z');
    CHECK(dest.size() == 4);
    CHECK(etl::string_view(dest) == etl::string_view("zzzz"));
  }
}

TEMPLATE_TEST_CASE("string: constexpr", "[string]", etl::static_string<8>,
                   etl::static_string<12>, etl::static_string<32>)
{
  constexpr TestType str1 {};

  STATIC_REQUIRE(str1.empty() == true);
  STATIC_REQUIRE(str1.capacity() == str1.max_size());
  STATIC_REQUIRE(str1.size() == 0);
  STATIC_REQUIRE(str1.length() == 0);

  constexpr auto str2 = []() {
    TestType str {};
    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    str.append(cptr, 4);
    return str;
  }();

  STATIC_REQUIRE(str2.empty() == false);
  STATIC_REQUIRE(str2.capacity() == str1.max_size());
  STATIC_REQUIRE(etl::strlen(str2.data()) == 4);
  STATIC_REQUIRE(str2.size() == 4);
  STATIC_REQUIRE(str2.length() == 4);
  STATIC_REQUIRE(str2[0] == 'C');
  STATIC_REQUIRE(str2[1] == '-');
  STATIC_REQUIRE(str2[2] == 's');
  STATIC_REQUIRE(str2[3] == 't');
}

TEMPLATE_TEST_CASE("string: operator[]", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
  TestType str {"abc"};
  REQUIRE(str[0] == 'a');
  REQUIRE(str[1] == 'b');
  REQUIRE(str[2] == 'c');
}

TEMPLATE_TEST_CASE("string: begin/end", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  TestType str {"aaa"};

  etl::for_each(str.begin(), str.end(),
                [](auto& c) { REQUIRE(c == char('a')); });
  for (auto const& c : str) { REQUIRE(c == char('a')); };
}

TEMPLATE_TEST_CASE("string: cbegin/cend", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
  TestType str {"aaa"};

  etl::for_each(str.cbegin(), str.cend(),
                [](auto const& c) { REQUIRE(c == char('a')); });
}

TEMPLATE_TEST_CASE("string: rbegin/rend", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
  TestType empty {};
  CHECK(empty.rbegin() == empty.rend());

  TestType str_1 {"test"};
  CHECK(str_1.rbegin() != str_1.rend());
  auto begin_1 = str_1.rbegin();
  CHECK(*begin_1++ == 't');
  CHECK(*begin_1++ == 's');
  CHECK(*begin_1++ == 'e');
  CHECK(*begin_1++ == 't');
  CHECK(begin_1 == str_1.rend());
}

TEMPLATE_TEST_CASE("string: crbegin/crend", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
  TestType empty {};
  CHECK(empty.crbegin() == empty.crend());

  TestType str_1 {"test"};
  CHECK(str_1.crbegin() != str_1.crend());
  auto begin_1 = str_1.crbegin();
  CHECK(*begin_1++ == 't');
  CHECK(*begin_1++ == 's');
  CHECK(*begin_1++ == 'e');
  CHECK(*begin_1++ == 't');
  CHECK(begin_1 == str_1.crend());
}

TEMPLATE_TEST_CASE("string: append(count, CharType)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  auto str = TestType();
  str.append(4, 'a');

  REQUIRE(str.size() == etl::size_t(4));
  REQUIRE(str.length() == etl::size_t(4));
  REQUIRE(str[0] == 'a');
  REQUIRE(str[1] == 'a');
  REQUIRE(str[2] == 'a');
  REQUIRE(str[3] == 'a');
}

TEMPLATE_TEST_CASE("string: append(const_pointer, count)", "[string]",
                   etl::static_string<8>, etl::static_string<12>,
                   etl::static_string<32>)
{
  TestType str {};

  // APPEND 4 CHARACTERS
  const char* cptr = "C-string";
  str.append(cptr, 4);

  REQUIRE(str.empty() == false);
  REQUIRE(str.capacity() == str.max_size());
  REQUIRE(str.size() == etl::size_t(4));
  REQUIRE(str.length() == etl::size_t(4));
  REQUIRE(str[0] == 'C');
  REQUIRE(str[1] == '-');
  REQUIRE(str[2] == 's');
  REQUIRE(str[3] == 't');
}

TEMPLATE_TEST_CASE("string: append(const_pointer)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  TestType str {};
  const char* cptr = "C-string";
  str.append(cptr);

  REQUIRE(str.size() == etl::strlen(cptr));
  REQUIRE(str.length() == etl::strlen(cptr));
  REQUIRE(str[0] == 'C');
  REQUIRE(str[1] == '-');
  REQUIRE(str[2] == 's');
  REQUIRE(str[3] == 't');
}

TEMPLATE_TEST_CASE("string: append(first,last)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty")
  {
    etl::string_view empty_src {""};

    TestType empty {};
    empty.append(begin(empty_src), end(empty_src));
    CHECK(empty.empty());

    TestType str {"abc"};
    str.append(begin(empty_src), end(empty_src));
    CHECK(etl::string_view(str) == etl::string_view("abc"));
  }

  SECTION("no nulls")
  {
    etl::string_view src {"_test"};

    TestType dest {"abc"};
    dest.append(begin(src), end(src));
    CHECK(etl::string_view(dest) == etl::string_view("abc_test"));
  }
}

TEMPLATE_TEST_CASE("string: append(string)", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty")
  {
    TestType empty_src {""};

    TestType empty {};
    empty.append(empty_src);
    CHECK(empty.empty());

    TestType str {"abc"};
    str.append(empty_src);
    CHECK(etl::string_view(str) == etl::string_view("abc"));
  }

  SECTION("no nulls")
  {
    TestType src {"_test"};

    TestType dest {"abc"};
    dest.append(src);
    CHECK(etl::string_view(dest) == etl::string_view("abc_test"));
  }
}

TEMPLATE_TEST_CASE("string: append(string,pos,count)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty")
  {
    TestType empty_src {""};

    TestType empty {};
    empty.append(empty_src, 0);
    CHECK(empty.empty());

    TestType str {"abc"};
    str.append(empty_src, 1);
    CHECK(etl::string_view(str) == etl::string_view("abc"));
  }

  SECTION("no nulls")
  {
    TestType src {"_test"};

    TestType dest {"abc"};
    dest.append(src, 2, 2);
    CHECK(etl::string_view(dest) == etl::string_view("abces"));
  }
}

TEMPLATE_TEST_CASE("string: append(string_view)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty")
  {
    etl::string_view empty_src {""};

    TestType empty {};
    empty.append(empty_src);
    CHECK(empty.empty());

    TestType str {"abc"};
    str.append(empty_src);
    CHECK(etl::string_view(str) == etl::string_view("abc"));
  }

  SECTION("no nulls")
  {
    etl::string_view src {"_test"};

    TestType dest {"abc"};
    dest.append(src);
    CHECK(etl::string_view(dest) == etl::string_view("abc_test"));
  }
}

TEMPLATE_TEST_CASE("string: append(string_view,pos,count)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty")
  {
    etl::string_view empty_src {};

    TestType empty {};
    empty.append(empty_src, 0);
    CHECK(empty.empty());
  }

  SECTION("no nulls")
  {
    etl::string_view src {"_test"};

    TestType dest {"abc"};
    dest.append(src, 2, 1);
    CHECK(etl::string_view(dest) == etl::string_view("abce"));
  }
}

TEMPLATE_TEST_CASE("string: operator+=", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("string")
  {
    TestType src {"_test"};
    TestType dest {"abc"};
    dest += src;
    CHECK(etl::string_view(dest) == etl::string_view("abc_test"));
  }

  SECTION("char")
  {
    auto src = 'a';
    TestType dest {"abc"};
    dest += src;
    CHECK(etl::string_view(dest) == etl::string_view("abca"));
  }

  SECTION("char const*")
  {
    auto const* src = "_test";
    TestType dest {"abc"};
    dest += src;
    CHECK(etl::string_view(dest) == etl::string_view("abc_test"));
  }

  SECTION("string_view")
  {
    etl::string_view src {"_test"};
    TestType dest {"abc"};
    dest += src;
    CHECK(etl::string_view(dest) == etl::string_view("abc_test"));
  }
}

TEMPLATE_TEST_CASE("string: algorithms", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  // setup
  TestType str {"aaaaaa"};
  etl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

  // test
  etl::for_each(str.cbegin(), str.cend(),
                [](auto const& c) { REQUIRE(c == 'b'); });

  REQUIRE(str.front() == 'b');
  REQUIRE(str.back() == 'b');
}

TEMPLATE_TEST_CASE("string: front/back", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  TestType str {"junk"};
  CHECK(str.front() == 'j');
  CHECK(etl::as_const(str).front() == 'j');

  CHECK(str.back() == 'k');
  CHECK(etl::as_const(str).back() == 'k');
}

TEMPLATE_TEST_CASE("string: data/c_str", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  TestType str {"junk"};
  CHECK(str.data() == str.c_str());
  CHECK(str.c_str() != nullptr);
  CHECK(str.c_str()[0] == 'j');
}

TEMPLATE_TEST_CASE("string: operator string_view", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  TestType str {"junk"};
  auto sv = etl::string_view {str};
  CHECK(sv.data()[0] == 'j');
}

TEMPLATE_TEST_CASE("string: clear", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  // setup
  TestType str {"junk"};
  REQUIRE(str.empty() == false);

  // test
  str.clear();
  REQUIRE(str.capacity() == str.max_size());
  REQUIRE(str.empty() == true);
  REQUIRE(str.size() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: push_back", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  TestType str {""};
  str.push_back('a');
  str.push_back('b');
  REQUIRE(str == TestType("ab"));
  REQUIRE(str.size() == 2);
}

TEMPLATE_TEST_CASE("string: pop_back", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  TestType str {"abc"};
  str.pop_back();
  str.pop_back();
  REQUIRE(str == TestType("a"));
  REQUIRE(str == "a");
  REQUIRE(str.size() == 1);
}

TEMPLATE_TEST_CASE("string: insert(index, count, CharType)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("on empty string")
  {
    auto str = TestType();
    str.insert(0, 4, 'a');
    CHECK(str.size() == 4);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("aaaa"));
  }

  SECTION("on filled string")
  {
    auto str = TestType("test");
    str.insert(0, 4, 'a');
    CHECK(str.size() == 8);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("aaaatest"));

    str = TestType("test");
    str.insert(1, 2, 'a');
    str.insert(0, 1, 'b');
    CHECK(str.size() == 7);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("btaaest"));

    str = TestType("test");
    str.insert(str.size(), 2, 'a');
    CHECK(str.size() == 6);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("testaa"));
  }

  SECTION("on full string")
  {
    auto str = TestType("");
    str.insert(0, str.capacity(), 'a');
    CHECK(str.full());
    CHECK(str.size() == str.capacity() - 1);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
  }
}

TEMPLATE_TEST_CASE("string: insert(index, CharType const*)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("on empty string")
  {
    auto str = TestType();
    str.insert(0, "aaaa");
    CHECK(str.size() == 4);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("aaaa"));
  }

  SECTION("on filled string")
  {
    auto str = TestType("test");
    str.insert(0, "abcd");
    CHECK(str.size() == 8);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("abcdtest"));

    str = TestType("test");
    str.insert(1, "aa");
    str.insert(0, "b");
    CHECK(str.size() == 7);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("btaaest"));

    str = TestType("test");
    str.insert(str.size(), "aa");
    CHECK(str.size() == 6);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("testaa"));
  }

  SECTION("on full string")
  {
    auto str = TestType("");
    for (etl::size_t i = 0; i < str.capacity(); ++i) { str.insert(0, "a"); }

    CHECK(str.full());
    CHECK(str.size() == str.capacity() - 1);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
  }
}

TEMPLATE_TEST_CASE("string: insert(index, CharType const*, count)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("on empty string")
  {
    auto str = TestType();
    str.insert(0, "aaaa", 4);
    CHECK(str.size() == 4);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("aaaa"));
  }

  SECTION("on filled string")
  {
    auto str = TestType("test");
    str.insert(0, "abcd", 3);
    CHECK(str.size() == 7);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("abctest"));

    str = TestType("test");
    str.insert(1, "aa", 2);
    str.insert(0, "b", 1);
    CHECK(str.size() == 7);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("btaaest"));

    str = TestType("test");
    str.insert(str.size(), "aa", 1);
    CHECK(str.size() == 5);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::string_view(str) == etl::string_view("testa"));
  }

  SECTION("on full string")
  {
    auto str = TestType("");
    for (etl::size_t i = 0; i < str.capacity(); ++i) { str.insert(0, "ab", 1); }

    CHECK(str.full());
    CHECK(str.size() == str.capacity() - 1);
    CHECK(etl::strlen(str.data()) == str.size());
    CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
  }
}

TEMPLATE_TEST_CASE("string: erase", "[string]", etl::static_string<32>,
                   etl::static_string<64>)
{
  SECTION("cpprefrence example")
  {
    TestType str = "This is an example";

    // Erase "This "
    str.erase(0, 5);
    CHECK(etl::string_view(str.data()) == etl::string_view("is an example"));

    // Erase ' '
    CHECK(*str.erase(etl::find(begin(str), end(str), ' ')) == 'a');
    CHECK(etl::string_view(str.data()) == etl::string_view("isan example"));

    // Trim from ' ' to the end of the string
    str.erase(str.find(' '));
    CHECK(etl::string_view(str.data()) == etl::string_view("isan"));
  }
}

TEMPLATE_TEST_CASE("string: resize", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("default char")
  {
    auto str = TestType();
    CHECK(str.empty() == true);

    // grow
    str.resize(2);
    CHECK(str.empty() == false);
    CHECK(str.size() == 2);
    CHECK(str[0] == '\0');
    CHECK(str[1] == '\0');

    // shrink
    str.resize(1);
    CHECK(str.empty() == false);
    CHECK(str.size() == 1);
    CHECK(str[0] == '\0');
  }

  SECTION("provided char")
  {
    auto str = TestType();
    CHECK(str.empty() == true);

    // grow
    str.resize(2, 'a');
    CHECK(str.empty() == false);
    CHECK(str.size() == 2);
    CHECK(str[0] == 'a');
    CHECK(str[1] == 'a');

    // shrink
    str.resize(1, 'a');
    CHECK(str.empty() == false);
    CHECK(str.size() == 1);
    CHECK(str[0] == 'a');
  }
}

TEMPLATE_TEST_CASE("string: starts_with", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using namespace etl::literals;

  SECTION("empty string")
  {
    auto str = TestType();
    CHECK_FALSE(str.starts_with("foo"_sv));
    CHECK_FALSE(str.starts_with("foo"));
    CHECK_FALSE(str.starts_with('f'));
  }

  SECTION("false")
  {
    auto str = TestType("test");
    CHECK_FALSE(str.starts_with("foo"_sv));
    CHECK_FALSE(str.starts_with("foo"));
    CHECK_FALSE(str.starts_with('f'));
  }

  SECTION("true")
  {
    auto str1 = TestType("foo");
    CHECK(str1.starts_with("foo"_sv));
    CHECK(str1.starts_with("foo"));
    CHECK(str1.starts_with('f'));

    auto str2 = TestType {"foobar"};
    CHECK(str2.starts_with("foo"_sv));
    CHECK(str2.starts_with("foo"));
    CHECK(str2.starts_with('f'));
  }
}

TEMPLATE_TEST_CASE("string: ends_with", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using namespace etl::literals;

  SECTION("empty string")
  {
    auto str = TestType();
    CHECK_FALSE(str.ends_with("foo"_sv));
    CHECK_FALSE(str.ends_with("foo"));
    CHECK_FALSE(str.ends_with('o'));
  }

  SECTION("false")
  {
    auto str = TestType("test");
    CHECK_FALSE(str.ends_with("foo"_sv));
    CHECK_FALSE(str.ends_with("foo"));
    CHECK_FALSE(str.ends_with('o'));
  }

  SECTION("true")
  {
    auto str = TestType("foo");
    CHECK(str.ends_with("foo"_sv));
    CHECK(str.ends_with("foo"));
    CHECK(str.ends_with('o'));

    auto str2 = TestType("barfoo");
    CHECK(str2.ends_with("foo"_sv));
    CHECK(str2.ends_with("foo"));
    CHECK(str2.ends_with('o'));
  }
}

TEMPLATE_TEST_CASE("string: substr", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using namespace etl::literals;

  SECTION("empty ")
  {
    auto str = TestType();
    CHECK(str.substr().size() == 0);
    CHECK(str.substr(1).size() == 0);
    CHECK(str.substr(10).size() == 0);
  }

  SECTION("non empty")
  {
    auto str = TestType("abcd");
    CHECK(str.size() == 4);
    CHECK(str.substr(0, 1).size() == 1);
    CHECK(str.substr(1).size() == 3);
    CHECK(str.substr(10).size() == 0);
  }
}

TEMPLATE_TEST_CASE("string: copy", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty")
  {
    char destination[32] = {};
    auto str             = TestType();
    CHECK(str.empty());
    CHECK(str.copy(destination, 0, 0) == 0);
    CHECK(str.copy(destination, 1, 0) == 0);
    CHECK(str.copy(destination, 10, 1) == 0);
  }

  SECTION("non empty")
  {
    char destination[32] = {};
    auto str             = TestType("abcd");
    CHECK(str.size() == 4);

    CHECK(str.copy(destination, 1, 100) == 0);
    CHECK(destination[0] == '\0');

    CHECK(str.copy(destination, 1, 0) == 1);
    CHECK(destination[0] == 'a');
    CHECK(destination[1] == '\0');

    CHECK(str.copy(destination, 2, 2) == 2);
    CHECK(destination[0] == 'c');
    CHECK(destination[1] == 'd');
    CHECK(destination[2] == '\0');

    CHECK(str.copy(destination, str.size()) == 4);
    CHECK(destination[0] == 'a');
    CHECK(destination[1] == 'b');
    CHECK(destination[2] == 'c');
    CHECK(destination[3] == 'd');
    CHECK(destination[4] == '\0');
  }
}

TEMPLATE_TEST_CASE("string: swap", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty")
  {
    auto lhs = TestType();
    auto rhs = TestType();
    CHECK(lhs.empty());
    CHECK(rhs.empty());

    lhs.swap(rhs);
    CHECK(lhs.empty());
    CHECK(rhs.empty());
  }

  SECTION("same size")
  {
    auto lhs = TestType {"abc"};
    auto rhs = TestType {"def"};
    CHECK(lhs.size() == rhs.size());

    etl::swap(lhs, rhs);
    CHECK(lhs.size() == rhs.size());

    CHECK(lhs == "def");
    CHECK(rhs == "abc");
  }

  SECTION("different size")
  {
    auto lhs = TestType("foo");
    auto rhs = TestType {"barbaz"};
    CHECK(lhs.size() != rhs.size());

    lhs.swap(rhs);
    CHECK(lhs.size() != rhs.size());

    CHECK(lhs == "barbaz");
    CHECK(rhs == "foo");
  }
}

TEMPLATE_TEST_CASE("string: compare(string)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty string same capacity")
  {
    auto lhs = TestType();
    auto rhs = TestType();

    CHECK(lhs.compare(rhs) == 0);
    CHECK(rhs.compare(lhs) == 0);
  }

  SECTION("empty string different capacity")
  {
    auto lhs = TestType();
    auto rhs = etl::static_string<2> {};

    CHECK(lhs.compare(rhs) == 0);
    CHECK(rhs.compare(lhs) == 0);
  }

  SECTION("same size equal")
  {
    auto const lhs = TestType("test");
    auto const rhs = TestType("test");

    CHECK(lhs.compare("test") == 0);
    CHECK(lhs.compare(etl::string_view("test")) == 0);
    CHECK(lhs.compare(rhs) == 0);
    CHECK(rhs.compare(lhs) == 0);

    CHECK(lhs.compare(1, 1, "test") < 0);
    CHECK(lhs.compare(1, 1, etl::string_view("test")) < 0);
    CHECK(lhs.compare(1, 1, rhs) < 0);
    CHECK(rhs.compare(1, 1, lhs) < 0);

    CHECK(lhs.compare(1, 1, rhs, 1, 1) == 0);
    CHECK(rhs.compare(1, 1, lhs, 1, 1) == 0);

    CHECK(TestType("te").compare(0, 2, etl::string_view("test"), 0, 2) == 0);
    CHECK(TestType("abcabc").compare(3, 3, etl::string_view("abc"), 0, 3) == 0);
    CHECK(TestType("abcabc").compare(3, 1, etl::string_view("abc"), 0, 3) < 0);
    CHECK(TestType("abcabc").compare(3, 3, etl::string_view("abc"), 0, 1) > 0);

    CHECK(TestType("abcabc").compare(3, 3, "abc", 3) == 0);
    CHECK(TestType("abcabc").compare(3, 1, "abc", 0, 3) < 0);
    CHECK(TestType("abcabc").compare(3, 3, "abc", 0, 1) > 0);
  }

  SECTION("different size equal")
  {
    auto const lhs = TestType("test");
    auto const rhs = TestType("te");

    CHECK(lhs.compare(rhs) > 0);
    CHECK(rhs.compare(etl::string_view("test")) < 0);

    auto other = etl::static_string<9> {"te"};
    CHECK(lhs.compare(other) > 0);
    CHECK(other.compare(etl::string_view("te")) == 0);
  }
}

TEMPLATE_TEST_CASE("string: find(string)", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType();
    CHECK(str.find(TestType(), 0) == 0);
    CHECK(str.find(TestType(), 1) == TestType::npos);
    CHECK(str.find(TestType {""}) == 0);
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.find(TestType {"abc"}, 0) == TestType::npos);
    CHECK(str.find(TestType {"abc"}, 1) == TestType::npos);
    CHECK(str.find(TestType {"abc"}) == TestType::npos);
  }

  SECTION("found")
  {
    auto str = TestType("abcd");
    CHECK(str.find(TestType {"abc"}, 0) == 0);
    CHECK(str.find(TestType {"bc"}, 1) == 1);
    CHECK(str.find(TestType {"cd"}) == 2);
  }
}

TEMPLATE_TEST_CASE("string: find(char const*)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType();
    CHECK(str.find("") == 0);
    CHECK(str.find("", 0) == 0);
    CHECK(str.find("", 1) == TestType::npos);
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.find("abc", 0) == TestType::npos);
    CHECK(str.find("abc", 1) == TestType::npos);
    CHECK(str.find("abc") == TestType::npos);
  }

  SECTION("found")
  {
    auto str = TestType("abcd");
    CHECK(str.find("abc", 0) == 0);
    CHECK(str.find("bc", 1) == 1);
    CHECK(str.find("cd") == 2);
  }
}

TEMPLATE_TEST_CASE("string: find(char)", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType();
    CHECK(str.find('a', 0) == TestType::npos);
    CHECK(str.find('a', 1) == TestType::npos);
    CHECK(str.find('a') == TestType::npos);
  }

  SECTION("not found")
  {
    auto str = TestType {"bcdef"};
    CHECK(str.find('a', 0) == TestType::npos);
    CHECK(str.find('a', 1) == TestType::npos);
    CHECK(str.find('a') == TestType::npos);
  }

  SECTION("found")
  {
    auto str = TestType("abcd");
    CHECK(str.find('a', 0) == 0);
    CHECK(str.find('b', 1) == 1);
    CHECK(str.find('c') == 2);
  }
}

TEMPLATE_TEST_CASE("string: rfind(string)", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType("test");
    CHECK(str.rfind(TestType()) == 0);
    CHECK(str.rfind(TestType(), 0) == 0);
    CHECK(str.rfind(TestType(), TestType::npos) == str.size());
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.rfind(TestType {"abc"}, 0) == TestType::npos);
    CHECK(str.rfind(TestType {"abc"}, 1) == TestType::npos);
    CHECK(str.rfind(TestType {"abc"}) == TestType::npos);
  }

  SECTION("found")
  {
    // auto const str = TestType ("test");
    // CHECK(str.rfind(TestType {"t"}) == 3);
    // CHECK(str.rfind(TestType {"est"}) == 1);

    // CHECK(str.rfind(TestType {"st"}, 12) == 2);
    // CHECK(str.rfind(TestType {"st"}, 12) == 2);
  }
}

TEMPLATE_TEST_CASE("string: rfind(char const*)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType("test");
    CHECK(str.rfind("") == 0);
    CHECK(str.rfind("", 0) == 0);
    CHECK(str.rfind("", TestType::npos) == str.size());
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.rfind("abc", 0) == TestType::npos);
    CHECK(str.rfind("abc", 1) == TestType::npos);
    CHECK(str.rfind("abc") == TestType::npos);
  }

  SECTION("found")
  {
    auto const str = TestType("test");
    CHECK(str.rfind("t") == 0);
    // CHECK(str.rfind("t", 1) == 3);
    // CHECK(str.rfind("est") == 1);

    // CHECK(str.rfind("st", 12) == 2);
    // CHECK(str.rfind("st", 12) == 2);
  }
}

TEMPLATE_TEST_CASE("string: find_first_of(string)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType();
    CHECK(str.find_first_of(TestType(), 0) == TestType::npos);
    CHECK(str.find_first_of(TestType(), 1) == TestType::npos);
    CHECK(str.find_first_of(TestType {""}) == TestType::npos);
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.find_first_of(TestType {"abc"}, 0) == TestType::npos);
    CHECK(str.find_first_of(TestType {"abc"}, 1) == TestType::npos);
    CHECK(str.find_first_of(TestType {"abc"}) == TestType::npos);
  }

  SECTION("found")
  {
    auto str = TestType("abcd");
    CHECK(str.find_first_of(TestType {"abc"}, 0) == 0);
    CHECK(str.find_first_of(TestType {"bc"}, 1) == 1);
    CHECK(str.find_first_of(TestType {"cd"}) == 2);
  }
}

TEMPLATE_TEST_CASE("string: find_first_of(char const*)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType();
    CHECK(str.find_first_of("", 0) == TestType::npos);
    CHECK(str.find_first_of("", 1) == TestType::npos);
    CHECK(str.find_first_of("") == TestType::npos);
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.find_first_of("abc", 0) == TestType::npos);
    CHECK(str.find_first_of("abc", 1) == TestType::npos);
    CHECK(str.find_first_of("abc") == TestType::npos);
  }

  SECTION("found")
  {
    auto str = TestType("abcd");
    CHECK(str.find_first_of("abc", 0) == 0);
    CHECK(str.find_first_of("bc", 1) == 1);
    CHECK(str.find_first_of("cd") == 2);
  }
}

TEMPLATE_TEST_CASE("string: find_first_of(char)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
  SECTION("empty string")
  {
    auto str = TestType();
    CHECK(str.find_first_of('a', 0) == TestType::npos);
    CHECK(str.find_first_of('a', 1) == TestType::npos);
    CHECK(str.find_first_of('a') == TestType::npos);
  }

  SECTION("not found")
  {
    auto str = TestType {"def"};
    CHECK(str.find_first_of('a', 0) == TestType::npos);
    CHECK(str.find_first_of('a', 1) == TestType::npos);
    CHECK(str.find_first_of('a') == TestType::npos);
  }

  SECTION("found")
  {
    auto str = TestType("abcd");
    CHECK(str.find_first_of('a', 0) == 0);
    CHECK(str.find_first_of('b', 1) == 1);
    CHECK(str.find_first_of('c') == 2);
  }
}

TEMPLATE_TEST_CASE("string: operator==/!=", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  SECTION("empty string same capacity")
  {
    auto lhs = TestType();
    auto rhs = TestType();

    CHECK(lhs == "");
    CHECK(lhs == rhs);
    CHECK_FALSE(lhs != rhs);
    CHECK(rhs == lhs);
    CHECK_FALSE(rhs != lhs);
  }

  SECTION("empty string different capacity")
  {
    auto lhs = TestType();
    auto rhs = etl::static_string<2> {};

    CHECK(lhs == "");
    CHECK(rhs == "");
    CHECK(lhs == rhs);
    CHECK_FALSE(lhs != rhs);
    CHECK_FALSE(lhs != "");
    CHECK(rhs == lhs);
    CHECK_FALSE(rhs != lhs);
  }
}

TEMPLATE_TEST_CASE("string: operator<", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using string = TestType;

  SECTION("empty string")
  {
    CHECK_FALSE(string {} < "");
    CHECK_FALSE(string {} < string {});
    CHECK_FALSE(string {} < etl::static_string<2> {});
    CHECK_FALSE(etl::static_string<4> {} < string {});
  }

  SECTION("string same capacity")
  {
    CHECK(string {"abc"} < "def");
    CHECK(string {"abc"} < string {"def"});
    CHECK(string {"abc"} < string {"defg"});
  }

  SECTION("string different capacity")
  {
    CHECK_FALSE(string {"def"} < "a");
    CHECK_FALSE(string {"def"} < etl::static_string<2> {"a"});
    CHECK(etl::static_string<2> {"a"} < string("test"));
  }
}

TEMPLATE_TEST_CASE("string: operator<=", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using string = TestType;

  SECTION("empty string")
  {
    CHECK(string {} <= "");
    CHECK(string {} <= string {});
    CHECK(string {} <= etl::static_string<2> {});
    CHECK(etl::static_string<4> {} <= string {});
  }

  SECTION("string same capacity")
  {
    CHECK(string {"abc"} <= "def");
    CHECK(string {"abc"} <= string {"def"});
    CHECK(string {"abc"} <= string {"defg"});
    CHECK(string {"abc"} <= string {"abc"});
  }

  SECTION("string different capacity")
  {
    CHECK_FALSE(string {"def"} <= "a");
    CHECK_FALSE(string {"def"} <= etl::static_string<2> {"a"});
    CHECK(etl::static_string<2> {"a"} <= string("test"));
  }
}

TEMPLATE_TEST_CASE("string: operator>", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using string = TestType;

  SECTION("empty string")
  {
    CHECK_FALSE(string {} > "");
    CHECK_FALSE(string {} > string {});
    CHECK_FALSE(string {} > etl::static_string<2> {});
    CHECK_FALSE(etl::static_string<4> {} > string {});
  }

  SECTION("string same capacity")
  {
    CHECK_FALSE(string {"abc"} > "def");
    CHECK_FALSE(string {"abc"} > string {"def"});
    CHECK_FALSE(string {"abc"} > string {"defg"});
    CHECK_FALSE(string {"abc"} > string {"abc"});
  }

  SECTION("string different capacity")
  {
    CHECK(string {"def"} > etl::static_string<2> {"a"});
    CHECK_FALSE(etl::static_string<2> {"a"} > string("test"));
  }
}

TEMPLATE_TEST_CASE("string: operator>=", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
  using string = TestType;

  SECTION("empty string")
  {
    CHECK(string {} >= "");
    CHECK(string {} >= string {});
    CHECK(string {} >= etl::static_string<2> {});
    CHECK(etl::static_string<4> {} >= string {});
  }

  SECTION("string same capacity")
  {
    CHECK(string {"abc"} >= "abc");
    CHECK(string {"abc"} >= string {"abc"});
    CHECK_FALSE(string {"abc"} >= string {"def"});
    CHECK_FALSE(string {"abc"} >= string {"defg"});
  }

  SECTION("string different capacity")
  {
    CHECK(string {"def"} >= etl::static_string<2> {"a"});
    CHECK_FALSE(etl::static_string<2> {"a"} >= string("test"));
  }
}