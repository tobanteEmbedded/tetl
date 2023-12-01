// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHARCONV_FROM_CHARS_HPP
#define TETL_CHARCONV_FROM_CHARS_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_strings/conversion.hpp>
#include <etl/_system_error/errc.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

/// \brief Primitive numerical input conversion
struct from_chars_result {
    char const* ptr {nullptr};
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
template <integral T>
    requires(not is_same_v<T, bool>)
[[nodiscard]] constexpr auto from_chars(char const* first, char const* last, T& value, int base = 10)
    -> from_chars_result
{
    auto const len               = static_cast<etl::size_t>(etl::distance(first, last));
    auto const [end, error, val] = detail::ascii_to_integer<T, false>(first, len, base);

    if (error == detail::ascii_to_integer_error::overflow) {
        return from_chars_result {.ptr = first, .ec = errc::result_out_of_range};
    }
    if (error == detail::ascii_to_integer_error::invalid_input) {
        return from_chars_result {.ptr = first, .ec = errc::invalid_argument};
    }

    value = val;
    return from_chars_result {.ptr = end, .ec = {}};
}

} // namespace etl

#endif // TETL_CHARCONV_FROM_CHARS_HPP
