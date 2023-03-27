/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHARCONV_TO_CHARS_HPP
#define TETL_CHARCONV_TO_CHARS_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_strings/conversion.hpp>
#include <etl/_system_error/errc.hpp>
#include <etl/_type_traits/enable_if.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

/// \brief Primitive numerical output conversion.
struct to_chars_result {
    char const* ptr { nullptr };
    etl::errc ec {};

    [[nodiscard]] friend constexpr auto operator==(to_chars_result const& l, to_chars_result const& r) noexcept -> bool
    {
        return l.ptr == r.ptr && l.ec == r.ec;
    }
};

/// Converts value into a character string by successively filling the range
/// [first, last), where [first, last) is required to be a valid range.
///
/// Integer formatters: value is converted to a string of digits in the given
/// base (with no redundant leading zeroes). Digits in the range 10..35
/// (inclusive) are represented as lowercase characters a..z. If value is less
/// than zero, the representation starts with a minus sign. The library provides
/// overloads for all signed and unsigned integer types and for the type char as
/// the type of the parameter value.
template <integral T>
    requires requires { not is_same_v<T, bool>; }
[[nodiscard]] constexpr auto to_chars(char* f, char* l, T val, int base = 10) -> to_chars_result
{
    auto const len = static_cast<etl::size_t>(etl::distance(f, l));
    auto const res = detail::int_to_ascii<T>(val, f, base, len);
    if (res.error == detail::int_to_ascii_error::none) { return to_chars_result { res.end, {} }; }
    return to_chars_result { l, errc::value_too_large };
}

[[nodiscard]] constexpr auto to_chars(char*, char*, bool, int = 10) -> to_chars_result = delete;

} // namespace etl

#endif // TETL_CHARCONV_TO_CHARS_HPP
