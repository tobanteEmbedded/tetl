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

#ifndef TAETL_CSTDLIB_HPP
#define TAETL_CSTDLIB_HPP

#include "etl/cassert.hpp"
#include "etl/cstddef.hpp"
#include "etl/cstring.hpp"

#include "etl/detail/cstddef_internal.hpp"

namespace etl
{
#if not defined(EXIT_SUCCESS)
/**
 * @brief Successful execution of a program.
 */
#define EXIT_SUCCESS 0
#endif

#if not defined(EXIT_FAILURE)
/**
 * @brief Unsuccessful execution of a program.
 */
#define EXIT_FAILURE 1
#endif

#if not defined(NULL)
/**
 * @brief The macro NULL is an implementation-defined null pointer constant,
 * which may be a prvalue of type nullptr_t.
 */
#define NULL nullptr
#endif

/**
 * @brief Return type for div, ldiv, lldiv & imaxdiv.
 */
struct div_t
{
  int quot;
  int rem;
};

/**
 * @brief Return type for div, ldiv, lldiv & imaxdiv.
 */
struct ldiv_t
{
  long quot;
  long rem;
};

/**
 * @brief Return type for div, ldiv, lldiv & imaxdiv.
 */
struct lldiv_t
{
  long long quot;
  long long rem;
};

/**
 * @brief Return type for div, ldiv, lldiv & imaxdiv.
 */
struct imaxdiv_t
{
  intmax_t quot;
  intmax_t rem;
};

/**
 * @brief Computes both the quotient and the remainder of the division of the
 * numerator x by the denominator y. The quotient is the result of the
 * expression x/y. The remainder is the result of the expression x%y.
 */
[[nodiscard]] constexpr auto div(int x, int y) noexcept -> std::div_t
{
  return {x / y, x % y};
}

/**
 * @brief Computes both the quotient and the remainder of the division of the
 * numerator x by the denominator y. The quotient is the result of the
 * expression x/y. The remainder is the result of the expression x%y.
 */
[[nodiscard]] constexpr auto div(long x, long y) noexcept -> std::ldiv_t
{
  return {x / y, x % y};
}

/**
 * @brief Computes both the quotient and the remainder of the division of the
 * numerator x by the denominator y. The quotient is the result of the
 * expression x/y. The remainder is the result of the expression x%y.
 */
[[nodiscard]] constexpr auto div(long long x, long long y) noexcept
  -> std::lldiv_t
{
  return {x / y, x % y};
}

/**
 * @brief Computes both the quotient and the remainder of the division of the
 * numerator x by the denominator y. The quotient is the result of the
 * expression x/y. The remainder is the result of the expression x%y.
 */
[[nodiscard]] constexpr auto ldiv(long x, long y) noexcept -> std::ldiv_t
{
  return {x / y, x % y};
}

/**
 * @brief Computes both the quotient and the remainder of the division of the
 * numerator x by the denominator y. The quotient is the result of the
 * expression x/y. The remainder is the result of the expression x%y.
 */
[[nodiscard]] constexpr auto lldiv(long long x, long long y) noexcept
  -> std::lldiv_t
{
  return {x / y, x % y};
}

/**
 * @brief Converts an integer value to a null-terminated string using the
 * specified base and stores the result in the array given by str parameter.
 *
 * @details If base is 10 and value is negative, the resulting string is
 * preceded with a minus sign (-). With any other base, value is always
 * considered unsigned.
 *
 * @todo Only base 10 is currently supported.
 */
constexpr auto itoa(int val, char* const buffer, int base) -> char*
{
  switch (base)
  {
  case 10:
  {
    auto digits10 = [](auto x) {
      auto result = 1;
      while (true)
      {
        if (x < 10) { return result; }
        if (x < 100) { return result + 1; }
        if (x < 1'000) { return result + 2; }
        if (x < 10'000) { return result + 3; }

        x /= 10'000;
        result += 4;
      }

      return result;
    };

    auto const result = digits10(val);
    auto pos          = result - 1;
    while (val >= 10)
    {
      auto const q  = val / 10;
      auto const r  = static_cast<char>(val % 10);
      buffer[pos--] = static_cast<char>('0' + r);
      val           = q;
    }

    *buffer = static_cast<char>(val + '0');
    return buffer;
  }
  default:
  {
    assert(false);
    return buffer;
  }
  }
}

namespace detail
{
/**
 * @brief Credit: https://www.geeksforgeeks.org/write-your-own-atoi
 */
template <typename T>
[[nodiscard]] constexpr auto ascii_to_integer(char const* string) noexcept -> T
{
  // Iterate through all characters
  // of input string and update result
  // take ASCII character of corosponding digit and
  // subtract the code from '0' to get numerical
  // value and multiply res by 10 to shuffle
  // digits left to update running total
  auto res = T {0};
  for (size_t i {0}; string[i] != '\0'; ++i)
  {
    auto const digit = string[i] - '0';
    res              = res * 10 + digit;
  }
  return res;
}
}  // namespace detail

/**
 * @brief Interprets an integer value in a byte string pointed to by str.
 * Discards any whitespace characters until the first non-whitespace character
 * is found, then takes as many characters as possible to form a valid integer
 * number representation and converts them to an integer value.
 */

[[nodiscard]] constexpr auto atoi(char const* string) noexcept -> int
{
  return detail::ascii_to_integer<int>(string);
}

[[nodiscard]] constexpr auto atol(char const* string) noexcept -> long
{
  return detail::ascii_to_integer<long>(string);
}

[[nodiscard]] constexpr auto atoll(char const* string) noexcept -> long long
{
  return detail::ascii_to_integer<long long>(string);
}
}  // namespace etl

#endif  // TAETL_CSTDLIB_HPP