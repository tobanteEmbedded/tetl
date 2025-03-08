// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHARCONV_TO_CHARS_HPP
#define TETL_CHARCONV_TO_CHARS_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_strings/from_integer.hpp>
#include <etl/_system_error/errc.hpp>

namespace etl {

/// \brief Primitive numerical output conversion.
struct to_chars_result {
    char const* ptr{nullptr};
    etl::errc ec{};

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return ec == etl::errc{}; }

    friend auto operator==(to_chars_result const&, to_chars_result const&) -> bool = default;
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
    requires(not same_as<T, bool>)
[[nodiscard]] constexpr auto to_chars(char* first, char* last, T val, int base = 10) -> to_chars_result
{
    constexpr auto options = strings::from_integer_options{.terminate_with_null = false};

    auto const len = static_cast<etl::size_t>(etl::distance(first, last));
    auto const res = strings::from_integer<T, options>(val, first, len, base);
    if (res.error == strings::from_integer_error::none) {
        return to_chars_result{res.end, {}};
    }
    return to_chars_result{
        .ptr = last,
        .ec  = errc::value_too_large,
    };
}

[[nodiscard]] constexpr auto to_chars(char*, char*, bool, int = 10) -> to_chars_result = delete;

} // namespace etl

#endif // TETL_CHARCONV_TO_CHARS_HPP
