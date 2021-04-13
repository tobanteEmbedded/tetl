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

#ifndef ETL_EXPERIMENTAL_TESTING_TESTING_HPP
#define ETL_EXPERIMENTAL_TESTING_TESTING_HPP

#include <stdio.h>
#include <stdlib.h>

#include "etl/format.hpp"

namespace etl::experimental::testing::detail
{
struct binary_test_case
{
  int line         = 0;
  char const* file = nullptr;
  char const* func = nullptr;
  char const* exp  = nullptr;
  char const* lhs  = nullptr;
  char const* rhs  = nullptr;
};

inline auto fail_binary_test(binary_test_case const& tc) -> void
{
  auto const* fmt = "%s:%d - %s\twith lhs: %s and rhs: %s\n";
  printf(fmt, tc.file, tc.line, tc.exp, tc.lhs, tc.rhs);
  exit(EXIT_FAILURE);  // NOLINT
}

template <typename T>
[[nodiscard]] auto format_argument(T const& t) -> ::etl::static_string<32>
{
  auto str = etl::static_string<32> {};
  ::etl::format_to(etl::back_inserter(str), "{}", t);
  return str;
}

}  // namespace etl::experimental::testing::detail

#if not defined(STR)
#define STR_IMPL(s) #s
#define STR(s) STR_IMPL(s)
#endif  // STR

#if not defined(MAKE_TEST_CASE)
#define MAKE_TEST_CASE(exp)                                                    \
  binary_test_case { __LINE__, __FILE__, TETL_FUNC_SIG, exp, }
#endif  // MAKE_TEST_CASE

#if not defined(EQUAL)
#define EQUAL(a, b)                                                            \
  do {                                                                         \
    if (!((a) == (b)))                                                         \
    {                                                                          \
      using namespace etl::experimental::testing::detail;                      \
      fail_binary_test(MAKE_TEST_CASE(STR((a) == (b))));                       \
    }                                                                          \
  } while (false);
#endif  // EQUAL

#if not defined(NOTEQUAL)
#define NOTEQUAL(a, b)                                                         \
  do {                                                                         \
    if (!((a) != (b)))                                                         \
    {                                                                          \
      using namespace etl::experimental::testing::detail;                      \
      auto l  = format_argument((a));                                          \
      auto r  = format_argument((b));                                          \
      auto tc = MAKE_TEST_CASE(STR((a) != (b)));                               \
      tc.lhs  = l.c_str();                                                     \
      tc.rhs  = r.c_str();                                                     \
      fail_binary_test(tc);                                                    \
    }                                                                          \
  } while (false);
#endif  // NOTEQUAL

#endif  // ETL_EXPERIMENTAL_TESTING_TESTING_HPP
