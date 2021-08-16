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
#ifndef TETL_STRING_STOD_HPP
#define TETL_STRING_STOD_HPP

#include "etl/_string/static_string.hpp"
#include "etl/_strings/conversion.hpp"

namespace etl {

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
template <size_t Capacity>
[[nodiscard]] constexpr auto stof(
    static_string<Capacity> const& str, size_t* pos = nullptr) -> float
{
    return detail::ascii_to_floating_point<float>(str, pos);
}

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
template <size_t Capacity>
[[nodiscard]] constexpr auto stod(
    static_string<Capacity> const& str, size_t* pos = nullptr) -> double
{
    return detail::ascii_to_floating_point<double>(str, pos);
}

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
template <size_t Capacity>
[[nodiscard]] constexpr auto stold(
    static_string<Capacity> const& str, size_t* pos = nullptr) -> long double
{
    return detail::ascii_to_floating_point<long double>(str, pos);
}

} // namespace etl

#endif // TETL_STRING_STOD_HPP