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

#ifndef TETL_CHARCONV_FROM_CHARS_HPP
#define TETL_CHARCONV_FROM_CHARS_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_strings/conversion.hpp"
#include "etl/_system_error/errc.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

/// \brief Primitive numerical input conversion
/// \module Strings
struct from_chars_result {
    char const* ptr { nullptr };
    etl::errc ec {};

    [[nodiscard]] friend constexpr auto operator==(
        from_chars_result const& l, from_chars_result const& r) noexcept -> bool
    {
        return l.ptr == r.ptr && l.ec == r.ec;
    }
};

/// \brief Analyzes the character sequence [first,last) for a pattern described
/// below. If no characters match the pattern or if the value obtained by
/// parsing the matched characters is not representable in the type of value,
/// value is unmodified, otherwise the characters matching the pattern are
/// interpreted as a text representation of an arithmetic value, which is stored
/// in value.
template <typename T>
[[nodiscard]] constexpr auto from_chars(
    char const* first, char const* last, T& value, int base = 10)
    -> enable_if_t<is_integral_v<T> && !is_same_v<T, bool>, from_chars_result>
{
    TETL_ASSERT(base == 10);
    ignore_unused(base);

    auto len = static_cast<::etl::size_t>(::etl::distance(first, last));
    auto res = detail::ascii_to_int_base10<T>(first, len);
    if (res.error == detail::ascii_to_int_error::none) {
        value = res.value;
        return from_chars_result { res.end };
    }
    if (res.error == detail::ascii_to_int_error::invalid_input) {
        return from_chars_result { first, errc::invalid_argument };
    }

    TETL_ASSERT(res.error == detail::ascii_to_int_error::overflow);
    return from_chars_result { first, errc::result_out_of_range };
}

} // namespace etl

#endif // TETL_CHARCONV_FROM_CHARS_HPP