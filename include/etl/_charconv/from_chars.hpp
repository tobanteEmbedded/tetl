// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHARCONV_FROM_CHARS_HPP
#define TETL_CHARCONV_FROM_CHARS_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/to_integer.hpp>
#include <etl/_system_error/errc.hpp>

namespace etl {

/// \brief Primitive numerical input conversion
struct from_chars_result {
    char const* ptr{nullptr};
    etl::errc ec{};

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return ec == etl::errc{}; }

    friend auto operator==(from_chars_result const&, from_chars_result const&) -> bool = default;
};

/// \brief Analyzes the character sequence [first,last) for a pattern described
/// below. If no characters match the pattern or if the value obtained by
/// parsing the matched characters is not representable in the type of value,
/// value is unmodified, otherwise the characters matching the pattern are
/// interpreted as a text representation of an arithmetic value, which is stored
/// in value.
template <integral Int>
    requires(not same_as<Int, bool>)
[[nodiscard]] constexpr auto from_chars(char const* first, char const* last, Int& value, int base = 10)
    -> from_chars_result
{
    constexpr auto options     = strings::to_integer_options{.skip_whitespace = false, .check_overflow = true};
    auto const [end, err, val] = strings::to_integer<Int, options>({first, last}, static_cast<Int>(base));

    if (err == strings::to_integer_error::overflow) {
        return from_chars_result{.ptr = first, .ec = errc::result_out_of_range};
    }
    if (err == strings::to_integer_error::invalid_input) {
        return from_chars_result{.ptr = first, .ec = errc::invalid_argument};
    }

    value = val;
    return from_chars_result{.ptr = end, .ec = {}};
}

} // namespace etl

#endif // TETL_CHARCONV_FROM_CHARS_HPP
