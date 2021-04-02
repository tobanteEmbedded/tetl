#ifndef ETL_EXPERIMENTAL_TESTING_TESTING_HPP
#define ETL_EXPERIMENTAL_TESTING_TESTING_HPP

#include <stdio.h>
#include <stdlib.h>

#include "etl/experimental/format/format.hpp"

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
  using namespace etl::experimental::format;
  auto str = etl::static_string<32> {};
  format_to(etl::back_inserter(str), "{}", t);
  return str;
}

}  // namespace etl::experimental::testing::detail

#if not defined(STR)
#define STR_IMPL(s) #s
#define STR(s) STR_IMPL(s)
#endif  // STR

#if not defined(MAKE_TEST_CASE)
#define MAKE_TEST_CASE(exp)                                                    \
  binary_test_case { __LINE__, __FILE__, __PRETTY_FUNCTION__, exp, }
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
