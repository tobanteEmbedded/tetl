/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/string_view.hpp"

TEST_CASE("string_view: construct default", "[string_view]")
{
  constexpr auto sv = etl::string_view {};

  REQUIRE(sv.data() == nullptr);
  STATIC_REQUIRE(sv.data() == nullptr);

  REQUIRE(sv.size() == 0);
  STATIC_REQUIRE(sv.size() == 0);

  REQUIRE(sv.length() == 0);
  STATIC_REQUIRE(sv.length() == 0);
}

TEST_CASE("string_view: construct(first,last)", "[string_view]")
{
  auto const sv   = etl::string_view {"test"};
  auto const copy = etl::string_view(begin(sv), end(sv));
  REQUIRE(copy.data() == sv.data());
  REQUIRE(copy.size() == sv.size());
  REQUIRE(copy == sv);
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
    auto const sv1 = etl::string_view {"test"};
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
    auto const sv = etl::string_view {"test"};
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
    auto const sv = etl::string_view {"test"};
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
    auto const sv = etl::string_view {"abc"};
    CHECK(*sv.rbegin() == 'c');
    CHECK(sv.rbegin() == sv.crbegin());
    CHECK(sv.rend() != sv.rbegin());
    CHECK(sv.rend() == sv.crend());
  }
}

TEST_CASE("string_view: ranged-for", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  auto counter  = etl::string_view::size_type {0};
  for (auto c : sv)
  {
    etl::ignore_unused(c);
    counter++;
  }

  REQUIRE(counter == sv.size());
  REQUIRE(counter == 4);
}

TEST_CASE("string_view: operator[]", "[string_view]")
{
  auto const sv1 = etl::string_view {"test"};
  REQUIRE(sv1[0] == 't');
  REQUIRE(sv1[1] == 'e');
  REQUIRE(sv1[2] == 's');
  REQUIRE(sv1[3] == 't');

  auto sv2 = etl::string_view {"tobi"};
  REQUIRE(sv2[0] == 't');
  REQUIRE(sv2[1] == 'o');
  REQUIRE(sv2[2] == 'b');
  REQUIRE(sv2[3] == 'i');
}

TEST_CASE("string_view: front", "[string_view]")
{
  auto const sv1 = etl::string_view {"test"};
  REQUIRE(sv1.front() == 't');

  auto sv2 = etl::string_view {"abc"};
  REQUIRE(sv2.front() == 'a');
}

TEST_CASE("string_view: back", "[string_view]")
{
  auto const sv1 = etl::string_view {"test"};
  REQUIRE(sv1.back() == 't');

  auto sv2 = etl::string_view {"abc"};
  REQUIRE(sv2.back() == 'c');
}

TEST_CASE("string_view: max_size", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE(sv.max_size() == etl::string_view::size_type(-1));
}

TEST_CASE("string_view: empty", "[string_view]")
{
  auto const t = etl::string_view {};
  REQUIRE(t.empty());

  auto const f = etl::string_view {"test"};
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
    auto sv = etl::string_view {"test"};
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
    auto sv = etl::string_view {"test"};
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
    auto sv        = etl::string_view {"test"};
    REQUIRE(sv.copy(&buffer[0], 2, 0) == 2);
    REQUIRE(buffer[0] == 't');
    REQUIRE(buffer[1] == 'e');
    REQUIRE(buffer[2] == 0);
    REQUIRE(buffer[3] == 0);
  }

  WHEN("offset = 1")
  {
    char buffer[4] = {};
    auto sv        = etl::string_view {"test"};
    REQUIRE(sv.copy(&buffer[0], 2, 1) == 2);
    REQUIRE(buffer[0] == 'e');
    REQUIRE(buffer[1] == 's');
    REQUIRE(buffer[2] == 0);
    REQUIRE(buffer[3] == 0);
  }

  WHEN("offset = 3")
  {
    char buffer[4] = {};
    auto sv        = etl::string_view {"test"};
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
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.starts_with(etl::string_view {"t"}));
    REQUIRE(sv.starts_with(etl::string_view {"te"}));
    REQUIRE(sv.starts_with(etl::string_view {"tes"}));
    REQUIRE(sv.starts_with(etl::string_view {"test"}));
  }

  WHEN("rhs == char")
  {
    auto const sv = etl::string_view {"abc"};
    REQUIRE(sv.starts_with('a'));
  }

  WHEN("rhs == char const*")
  {
    auto const sv = etl::string_view {"abc"};
    REQUIRE(sv.starts_with("a"));
    REQUIRE(sv.starts_with("ab"));
    REQUIRE(sv.starts_with("abc"));
  }
}

TEST_CASE("string_view: ends_with", "[string_view]")
{
  WHEN("rhs == string_view")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.ends_with(etl::string_view {"t"}));
    REQUIRE(sv.ends_with(etl::string_view {"st"}));
    REQUIRE(sv.ends_with(etl::string_view {"est"}));
    REQUIRE(sv.ends_with(etl::string_view {"test"}));
  }

  WHEN("rhs == char")
  {
    auto const sv = etl::string_view {"abc"};
    REQUIRE(sv.ends_with('c'));
    REQUIRE_FALSE(sv.ends_with('a'));
  }

  WHEN("rhs == char const*")
  {
    auto const sv = etl::string_view {"abc"};
    REQUIRE(sv.ends_with("c"));
    REQUIRE(sv.ends_with("bc"));
    REQUIRE(sv.ends_with("abc"));
  }
}

TEST_CASE("string_view: find", "[string_view]")
{
  WHEN("rhs == string_view")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find(etl::string_view {"t"}) == 0);
    REQUIRE(sv.find(etl::string_view {"est"}) == 1);

    REQUIRE(sv.find(etl::string_view {"st"}, 1) == 2);
    REQUIRE(sv.find(etl::string_view {"st"}, 2) == 2);
  }

  WHEN("rhs == char")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find('t') == 0);
    REQUIRE(sv.find('e') == 1);

    REQUIRE(sv.find('s') == 2);
    REQUIRE(sv.find('s', 2) == 2);
  }

  WHEN("rhs == const char* s, size_type pos, size_type count")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find("t", 0, 1) == 0);
    REQUIRE(sv.find("est", 0, 3) == 1);

    REQUIRE(sv.find("x", 0, 1) == etl::string_view::npos);
    REQUIRE(sv.find("foo", 0, 3) == etl::string_view::npos);
  }

  WHEN("rhs == const char* s, size_type pos")
  {
    auto const sv = etl::string_view {"test"};
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
//     //     auto const sv = etl::string_view {"test"};
//     //     REQUIRE(sv.rfind(etl::string_view {"t"}) == 3);
//     //     REQUIRE(sv.rfind(etl::string_view {"est"}) == 1);

//     //     REQUIRE(sv.rfind(etl::string_view {"st"}, 12) == 2);
//     //     REQUIRE(sv.rfind(etl::string_view {"st"}, 12) == 2);
//     // }

//     WHEN("rhs == char")
//     {
//         auto const sv = etl::string_view {"test"};
//         REQUIRE(sv.rfind('t') == 3);
//         REQUIRE(sv.rfind('e') == 1);

//         REQUIRE(sv.rfind('s') == 2);
//         REQUIRE(sv.rfind('s', 2) == 2);
//     }

//     WHEN("rhs == const char* s, size_type pos, size_type count")
//     {
//         auto const sv = etl::string_view {"test"};
//         REQUIRE(sv.rfind("t", etl::string_view::npos, 1) == 3);
//         REQUIRE(sv.rfind("est", etl::string_view::npos, 3) == 1);

//         REQUIRE(sv.rfind("x", etl::string_view::npos, 1) ==
//         etl::string_view::npos); REQUIRE(sv.rfind("foo",
//         etl::string_view::npos, 3) == etl::string_view::npos);
//     }

//     WHEN("rhs == const char* s, size_type pos")
//     {
//         auto const sv = etl::string_view {"test"};
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
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_first_of(etl::string_view {"t"}) == 0);
    REQUIRE(sv.find_first_of(etl::string_view {"est"}) == 0);

    REQUIRE(sv.find_first_of(etl::string_view {"t"}, 1) == 3);
    REQUIRE(sv.find_first_of(etl::string_view {"st"}, 2) == 2);
  }

  WHEN("rhs == char")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_first_of('t') == 0);
    REQUIRE(sv.find_first_of('e') == 1);

    REQUIRE(sv.find_first_of('t', 1) == 3);
    REQUIRE(sv.find_first_of('s') == 2);
  }

  WHEN("rhs == const char* s, size_type pos, size_type count")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_first_of("t", 0, 1) == 0);
    REQUIRE(sv.find_first_of("est", 0, 3) == 0);

    REQUIRE(sv.find_first_of("x", 0, 1) == etl::string_view::npos);
    REQUIRE(sv.find_first_of("foo", 0, 3) == etl::string_view::npos);
  }

  WHEN("rhs == const char* s, size_type pos")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_first_of("t", 1) == 3);
    REQUIRE(sv.find_first_of("est", 1) == 1);

    REQUIRE(sv.find_first_of("x", 0) == etl::string_view::npos);
    REQUIRE(sv.find_first_of("foo", 0) == etl::string_view::npos);

    REQUIRE(sv.find_first_of("xxxxx", 0) == etl::string_view::npos);
    REQUIRE(sv.find_first_of("foobarbaz", 0) == etl::string_view::npos);
  }
}

TEST_CASE("string_view: find_last_of", "[string_view]")
{
  WHEN("rhs == string_view")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_last_of(etl::string_view {"t"}) == 3);
    REQUIRE(sv.find_last_of(etl::string_view {"est"}) == 3);

    REQUIRE(sv.find_last_of(etl::string_view {"t"}, 1) == 0);
    REQUIRE(sv.find_last_of(etl::string_view {"st"}, 2) == 2);
  }

  WHEN("rhs == char")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_last_of('t') == 3);
    REQUIRE(sv.find_last_of('e') == 1);
    REQUIRE(sv.find_last_of('s') == 2);
  }

  WHEN("rhs == const char* s, size_type pos, size_type count")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_last_of("t", 12, 1) == 3);
    REQUIRE(sv.find_last_of("es", 12, 2) == 2);

    REQUIRE(sv.find_last_of("x", 0, 1) == etl::string_view::npos);
    REQUIRE(sv.find_last_of("foo", 0, 3) == etl::string_view::npos);
  }

  WHEN("rhs == const char* s, size_type pos")
  {
    auto const sv = etl::string_view {"test"};
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
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_last_not_of(etl::string_view {"t"}) == 2);
    REQUIRE(sv.find_last_not_of(etl::string_view {"est"}) == sv.npos);
    REQUIRE(sv.find_last_not_of(etl::string_view {"s"}, 2) == 1);
  }

  WHEN("rhs == char")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_last_not_of('t') == 2);
    REQUIRE(sv.find_last_not_of('e') == 3);
    REQUIRE(sv.find_last_not_of('s') == 3);
  }

  WHEN("rhs == const char* s, size_type pos, size_type count")
  {
    auto const npos = etl::string_view::npos;
    auto const sv   = etl::string_view {"test"};
    REQUIRE(sv.find_last_not_of("t", npos, 1) == 2);
    REQUIRE(sv.find_last_not_of("es", npos, 2) == 3);
    REQUIRE(sv.find_last_not_of("est", npos, 4) == npos);
    REQUIRE(sv.find_last_not_of("tes", npos, 4) == npos);
  }

  WHEN("rhs == const char* s, size_type pos")
  {
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.find_last_not_of("t") == 2);
    REQUIRE(sv.find_last_not_of("es") == 3);

    REQUIRE(sv.find_last_not_of("tes") == etl::string_view::npos);
    REQUIRE(sv.find_last_not_of("est") == etl::string_view::npos);
  }
}

TEST_CASE("string_view: substr", "[string_view]")
{
  auto const sv = etl::string_view {"test"};

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
  SECTION("empty string same capacity")
  {
    auto lhs = etl::string_view();
    auto rhs = etl::string_view();

    CHECK(lhs.compare(rhs) == 0);
    CHECK(rhs.compare(lhs) == 0);
  }

  SECTION("same size equal")
  {
    auto const lhs = etl::string_view("test");
    auto const rhs = etl::string_view("test");

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

    CHECK(etl::string_view("te").compare(0, 2, etl::string_view("test"), 0, 2)
          == 0);
    CHECK(
      etl::string_view("abcabc").compare(3, 3, etl::string_view("abc"), 0, 3)
      == 0);
    CHECK(
      etl::string_view("abcabc").compare(3, 1, etl::string_view("abc"), 0, 3)
      < 0);
    CHECK(
      etl::string_view("abcabc").compare(3, 3, etl::string_view("abc"), 0, 1)
      > 0);

    CHECK(etl::string_view("abcabc").compare(3, 3, "abc", 3) == 0);
    CHECK(etl::string_view("abcabc").compare(3, 1, "abc", 0, 3) < 0);
    CHECK(etl::string_view("abcabc").compare(3, 3, "abc", 0, 1) > 0);
  }

  SECTION("different size equal")
  {
    auto const lhs = etl::string_view("test");
    auto const rhs = etl::string_view("te");

    CHECK(lhs.compare(rhs) > 0);
    CHECK(rhs.compare(etl::string_view("test")) < 0);
  }
}

TEST_CASE("string_view: operator==", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE(sv == sv);
  REQUIRE(sv == etl::string_view {"test"});
  REQUIRE_FALSE(sv == sv.substr(0, 1));
  REQUIRE_FALSE(sv == etl::string_view {"abc"});
}

TEST_CASE("string_view: operator!=", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE_FALSE(sv != sv);
  REQUIRE_FALSE(sv != etl::string_view {"test"});
  REQUIRE(sv != sv.substr(0, 1));
  REQUIRE(sv != etl::string_view {"abc"});
}

TEST_CASE("string_view: operator<", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE_FALSE(sv < sv);
  REQUIRE(etl::string_view {""} < sv);
  REQUIRE(sv.substr(0, 1) < sv);
  REQUIRE(etl::string_view {"abc"} < sv);
}

TEST_CASE("string_view: operator<=", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE(sv <= sv);
  REQUIRE(etl::string_view {""} <= sv);
  REQUIRE(sv.substr(0, 1) <= sv);
  REQUIRE(etl::string_view {"abc"} <= sv);
}

TEST_CASE("string_view: operator>", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE_FALSE(sv > sv);
  REQUIRE(etl::string_view {"xxxxxx"} > sv);
  REQUIRE(sv > sv.substr(0, 1));
  REQUIRE(sv > etl::string_view {"abc"});
}

TEST_CASE("string_view: operator>=", "[string_view]")
{
  auto const sv = etl::string_view {"test"};
  REQUIRE(sv >= sv);
  REQUIRE(etl::string_view {"xxxxxx"} >= sv);
  REQUIRE(sv >= sv.substr(0, 1));
  REQUIRE(sv >= etl::string_view {"abc"});
}

TEST_CASE("string_view: operator\"\"", "[string_view]")
{
  using namespace etl::literals;
  auto const sv = "test"_sv;
  REQUIRE(sv.size() >= 4);
  REQUIRE(sv[0] >= 't');
}
