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
 * @brief Checks if the given character is an alphanumeric character as classified by the
 * default C locale.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isalnum
 *
 * @return Non-zero value if the character is an alphanumeric character, 0 otherwise.
 */
[[nodiscard]] constexpr auto isalpha(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto is_lower = ch >= 'a' && ch <= 'z';
    auto is_upper = ch >= 'A' && ch <= 'Z';

    return static_cast<int>(is_lower || is_upper);
}
}  // namespace etl
#endif  // TAETL_CCTYPE_HPP
