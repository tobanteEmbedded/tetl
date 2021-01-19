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

#include "etl/version.hpp"

TEST_CASE("version: language_standard", "[vector]")
{
  using etl::language_standard;

  auto less = [](auto lhs, auto rhs) {
    return static_cast<long>(lhs) < static_cast<long>(rhs);
  };

  auto greater = [](auto lhs, auto rhs) {
    return static_cast<long>(lhs) > static_cast<long>(rhs);
  };

  WHEN("C++11")
  {
    REQUIRE(greater(language_standard::cpp_11, language_standard::cpp_98));

    REQUIRE(less(language_standard::cpp_11, language_standard::cpp_14));
    REQUIRE(less(language_standard::cpp_11, language_standard::cpp_17));
    REQUIRE(less(language_standard::cpp_11, language_standard::cpp_20));
  }

  WHEN("C++14")
  {
    REQUIRE(greater(language_standard::cpp_14, language_standard::cpp_11));

    REQUIRE(less(language_standard::cpp_14, language_standard::cpp_17));
    REQUIRE(less(language_standard::cpp_14, language_standard::cpp_20));
  }

  WHEN("C++17")
  {
    REQUIRE(greater(language_standard::cpp_17, language_standard::cpp_11));
    REQUIRE(greater(language_standard::cpp_17, language_standard::cpp_14));

    REQUIRE(less(language_standard::cpp_17, language_standard::cpp_20));
  }

  WHEN("C++20")
  {
    REQUIRE(greater(language_standard::cpp_20, language_standard::cpp_98));
    REQUIRE(greater(language_standard::cpp_20, language_standard::cpp_11));
    REQUIRE(greater(language_standard::cpp_20, language_standard::cpp_14));
    REQUIRE(greater(language_standard::cpp_20, language_standard::cpp_17));
  }
}

TEST_CASE("version: current_standard", "[vector]")
{
#if defined(TAEL_CPP_STANDARD_17)
  REQUIRE(etl::current_standard == etl::language_standard::cpp_17);
#endif

#if defined(TAEL_CPP_STANDARD_20)
  REQUIRE(etl::current_standard == etl::language_standard::cpp_20);
#endif
}
