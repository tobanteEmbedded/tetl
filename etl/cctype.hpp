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

/**
 * @brief Checks if the given character is whitespace character as classified by the
 * default C locale.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isspace
 *
 * @return Non-zero value if the character is a whitespace character, zero otherwise.
 */
[[nodiscard]] constexpr auto isspace(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto const space           = ch == ' ';
    auto const form_feed       = ch == '\f';
    auto const line_feed       = ch == '\n';
    auto const carriage_return = ch == '\r';
    auto const horizontal_tab  = ch == '\t';
    auto const vertical_tab    = ch == '\v';

    return static_cast<int>(space || form_feed || line_feed || carriage_return
                            || horizontal_tab || vertical_tab);
}

/**
 * @brief Checks if the given character is a blank character as classified by the
 * currently installed C locale. Blank characters are whitespace characters used to
 * separate words within a sentence. In the default C locale, only space (0x20) and
 * horizontal tab (0x09) are classified as blank characters.
 *
 * https://en.cppreference.com/w/cpp/string/byte/isblank
 *
 * @return Non-zero value if the character is a blank character, zero otherwise.
 */
[[nodiscard]] constexpr auto isblank(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto const space          = ch == ' ';
    auto const horizontal_tab = ch == '\t';

    return static_cast<int>(space || horizontal_tab);
}

/**
 * @brief Checks if the given character is a punctuation character as classified by the
 * current C locale.
 *
 * The default C locale classifies the characters !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ as
 * punctuation.
 *
 * https://en.cppreference.com/w/cpp/string/byte/ispunct
 *
 * @return Non-zero value if the character is a punctuation character, zero otherwise.
 */
[[nodiscard]] constexpr auto ispunct(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    auto const sec_1 = ch >= '!' && ch <= '/';
    auto const sec_2 = ch >= ':' && ch <= '@';
    auto const sec_3 = ch >= '[' && ch <= '`';
    auto const sec_4 = ch >= '{' && ch <= '~';

    return static_cast<int>(sec_1 || sec_2 || sec_3 || sec_4);
}

/**
 * @brief Converts the given character to lowercase according to the character conversion
 * rules defined by the default C locale.
 *
 * In the default "C" locale, the following uppercase letters ABCDEFGHIJKLMNOPQRSTUVWXYZ
 * are replaced with respective lowercase letters abcdefghijklmnopqrstuvwxyz.
 *
 * https://en.cppreference.com/w/cpp/string/byte/tolower
 *
 * @return Lowercase version of ch or unmodified ch if no lowercase version is listed in
 * the current C locale.
 */
[[nodiscard]] constexpr auto tolower(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    if (isupper(ch) != 0) { return static_cast<int>(ch + 32); }
    return static_cast<int>(ch);
}

/**
 * @brief Converts the given character to uppercase according to the character conversion
 * rules defined by the default C locale.
 *
 * In the default "C" locale, the following lowercase letters abcdefghijklmnopqrstuvwxyz
 * are replaced with respective uppercase letters ABCDEFGHIJKLMNOPQRSTUVWXYZ.
 *
 * https://en.cppreference.com/w/cpp/string/byte/toupper
 *
 * @return Converted character or ch if no uppercase version is defined by the current C
 * locale.
 */
[[nodiscard]] constexpr auto toupper(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    assert(static_cast<unsigned char>(ch) == ch);

    if (islower(ch) != 0) { return static_cast<int>(ch - 32); }
    return static_cast<int>(ch);
}
}  // namespace etl
#endif  // TAETL_CCTYPE_HPP
