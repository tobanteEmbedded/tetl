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
#ifndef TETL_STRING_STOI_HPP
#define TETL_STRING_STOI_HPP

#include "etl/_string/static_string.hpp"
#include "etl/_strings/conversion.hpp"

namespace etl {

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoi(static_string<Capacity> const& str,
    size_t* pos = nullptr, int base = 10) -> int
{
    ignore_unused(pos, base);
    auto const res = detail::ascii_to_int_base10<int>(str.c_str());
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stol(static_string<Capacity> const& str,
    size_t* pos = nullptr, int base = 10) -> long
{
    ignore_unused(pos, base);
    auto const res = detail::ascii_to_int_base10<long>(str.c_str());
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoll(static_string<Capacity> const& str,
    size_t* pos = nullptr, int base = 10) -> long long
{
    ignore_unused(pos, base);
    auto const res = detail::ascii_to_int_base10<long long>(str.c_str());
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoul(static_string<Capacity> const& str,
    size_t* pos = nullptr, int base = 10) -> unsigned long
{
    ignore_unused(pos, base);
    auto const res = detail::ascii_to_int_base10<unsigned long>(str.c_str());
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoull(static_string<Capacity> const& str,
    size_t* pos = nullptr, int base = 10) -> unsigned long long
{
    ignore_unused(pos, base);
    auto const res
        = detail::ascii_to_int_base10<unsigned long long>(str.c_str());
    return res.value;
}

} // namespace etl

#endif // TETL_STRING_STOI_HPP