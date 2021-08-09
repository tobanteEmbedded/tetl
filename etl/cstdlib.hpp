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

#if not defined(TETL_CSTDLIB_HPP)
#define TETL_CSTDLIB_HPP

#include "etl/version.hpp"

#include "etl/cassert.hpp"
#include "etl/cmath.hpp"
#include "etl/cstddef.hpp"
#include "etl/cstring.hpp"

#include "etl/detail/cstddef_internal.hpp"
#include "etl/detail/strings/conversion.hpp"

namespace etl {
#if not defined(EXIT_SUCCESS)

/// \brief Successful execution of a program.
#define EXIT_SUCCESS 0
#endif

#if not defined(EXIT_FAILURE)

/// \brief Unsuccessful execution of a program.
#define EXIT_FAILURE 1
#endif

#if not defined(NULL)

/// \brief The macro NULL is an implementation-defined null pointer constant,
/// which may be a prvalue of type nullptr_t.
#define NULL nullptr
#endif

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct div_t {
    int quot;
    int rem;
};

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct ldiv_t {
    long quot;
    long rem;
};

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct lldiv_t {
    long long quot;
    long long rem;
};

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct imaxdiv_t {
    intmax_t quot;
    intmax_t rem;
};

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto div(int x, int y) noexcept -> div_t
{
    return { x / y, x % y };
}

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto div(long x, long y) noexcept -> ldiv_t
{
    return { x / y, x % y };
}

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto div(long long x, long long y) noexcept -> lldiv_t
{
    return { x / y, x % y };
}

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto ldiv(long x, long y) noexcept -> ldiv_t
{
    return { x / y, x % y };
}

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto lldiv(long long x, long long y) noexcept -> lldiv_t
{
    return { x / y, x % y };
}

/// \brief Converts an integer value to a null-terminated string using the
/// specified base and stores the result in the array given by str parameter.
///
/// \details If base is 10 and value is negative, the resulting string is
/// preceded with a minus sign (-). With any other base, value is always
/// considered unsigned.
///
/// \todo Only base 10 is currently supported.
constexpr auto itoa(int val, char* const buffer, int base) -> char*
{
    auto res = detail::int_to_ascii<int>(val, buffer, base);
    TETL_ASSERT(res.error == detail::int_to_ascii_error::none);
    ignore_unused(res);
    return buffer;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atoi(char const* string) noexcept -> int
{
    auto const result = detail::ascii_to_int_base10<int>(string);
    return result.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atol(char const* string) noexcept -> long
{
    auto const result = detail::ascii_to_int_base10<long>(string);
    return result.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atoll(char const* string) noexcept -> long long
{
    auto const result = detail::ascii_to_int_base10<long long>(string);
    return result.value;
}

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success. If the converted value falls out of range of corresponding return
/// type, range error occurs and HUGE_VAL, HUGE_VALF or HUGE_VALL is returned.
/// If no conversion can be performed, `0` is returned and *last is set to str.
[[nodiscard]] constexpr auto strtof(
    const char* str, char const** last = nullptr) noexcept -> float
{
    return detail::ascii_to_floating_point<float>(str, last);
}

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success. If the converted value falls out of range of corresponding return
/// type, range error occurs and HUGE_VAL, HUGE_VALF or HUGE_VALL is returned.
/// If no conversion can be performed, `0` is returned and *last is set to str.
[[nodiscard]] constexpr auto strtod(
    const char* str, char const** last = nullptr) noexcept -> double
{
    return detail::ascii_to_floating_point<double>(str, last);
}

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success. If the converted value falls out of range of corresponding return
/// type, range error occurs and HUGE_VAL, HUGE_VALF or HUGE_VALL is returned.
/// If no conversion can be performed, `0` is returned and *last is set to str.
[[nodiscard]] constexpr auto strtold(
    const char* str, char const** last = nullptr) noexcept -> long double
{
    return detail::ascii_to_floating_point<long double>(str, last);
}

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
[[nodiscard]] constexpr auto labs(long n) noexcept -> long
{
    return detail::abs_impl<long>(n);
}

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
[[nodiscard]] constexpr auto llabs(long long n) noexcept -> long long
{
    return detail::abs_impl<long long>(n);
}
} // namespace etl

#endif // TETL_CSTDLIB_HPP