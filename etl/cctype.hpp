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

#ifndef TAETL_CCTYPE_HPP
#define TAETL_CCTYPE_HPP

#include "cassert.hpp"
#include "limits.hpp"

namespace etl
{
/**
 * @brief Checks if the given character is an alphanumeric character as classified by the
 * default C locale.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isalnum
 *
 * @return Non-zero value if the character is an alphanumeric character, 0 otherwise.
 */
[[nodiscard]] constexpr auto isalnum(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto is_digit = ch >= '0' && ch <= '9';
    auto is_lower = ch >= 'a' && ch <= 'z';
    auto is_upper = ch >= 'A' && ch <= 'Z';

    return static_cast<int>(is_digit || is_lower || is_upper);
}

/**
 * @brief Checks if the given character is an alphabetic character as classified by the
 * default C locale.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isalpha
 *
 * @return Non-zero value if the character is an alphabetic character, 0 otherwise.
 */
[[nodiscard]] constexpr auto isalpha(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto is_lower = ch >= 'a' && ch <= 'z';
    auto is_upper = ch >= 'A' && ch <= 'Z';

    return static_cast<int>(is_lower || is_upper);
}

/**
 * @brief Checks if the given character is classified as a lowercase character according
 * to the default C locale.
 *
 * https://en.cppreference.com/w/cpp/string/byte/islower
 *
 * @return Non-zero value if the character is a lowercase letter, zero otherwise.
 */
[[nodiscard]] constexpr auto islower(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>(ch >= 'a' && ch <= 'z');
}

/**
 * @brief Checks if the given character is classified as a uppercase character according
 * to the default C locale.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isupper
 *
 * @return Non-zero value if the character is a uppercase letter, zero otherwise.
 */
[[nodiscard]] constexpr auto isupper(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>(ch >= 'A' && ch <= 'Z');
}

/**
 * @brief Checks if the given character is one of the 10 decimal digits: 0123456789.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isdigit
 *
 * @return Non-zero value if the character is a numeric character, zero otherwise.
 */
[[nodiscard]] constexpr auto isdigit(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>(ch >= '0' && ch <= '9');
}

/**
 * @brief Checks if the given character is a hexadecimal numeric character
 * (0123456789abcdefABCDEF).
 *
 * https://en.cppreference.com/w/cpp/string/byte/isxdigit
 *
 * @return Non-zero value if the character is a hexadecimal numeric character, zero
 * otherwise.
 */
[[nodiscard]] constexpr auto isxdigit(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto const is_digit     = ch >= '0' && ch <= '9';
    auto const is_hex_lower = ch >= 'a' && ch <= 'f';
    auto const is_hex_upper = ch >= 'A' && ch <= 'F';

    return static_cast<int>(is_digit || is_hex_lower || is_hex_upper);
}
}  // namespace etl
#endif  // TAETL_CCTYPE_HPP
