/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHARCONV_FROM_CHARS_HPP
#define TETL_CHARCONV_FROM_CHARS_HPP

#include "etl/_cassert/macro.hpp"
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

    [[nodiscard]] friend constexpr auto operator==(from_chars_result const& l, from_chars_result const& r) noexcept
        -> bool
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
template <typename T, enable_if_t<is_integral_v<T> && !is_same_v<T, bool>, int> = 0>
[[nodiscard]] constexpr auto from_chars(char const* first, char const* last, T& value, int base = 10)
    -> from_chars_result
{
    TETL_ASSERT(base == 10);
    ignore_unused(base);

    auto len = static_cast<etl::size_t>(etl::distance(first, last));
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