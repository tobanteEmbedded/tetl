// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_IN_RANGE_HPP
#define TETL_UTILITY_IN_RANGE_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_utility/cmp_greater_equal.hpp>
#include <etl/_utility/cmp_less_equal.hpp>

namespace etl {

/// \brief Returns true if the value of t is in the range of values that can be
/// represented in R, that is, if t can be converted to R without data loss.
///
/// \details It is a compile-time error if either T or R is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type). This function cannot be used with etl::byte, char, char8_t, char16_t,
/// char32_t, wchar_t and bool.
///
/// https://en.cppreference.com/w/cpp/utility/in_range
template <typename R, typename T>
    requires etl::detail::integer_and_not_char<T>
[[nodiscard]] constexpr auto in_range(T t) noexcept -> bool
{
    using limits = etl::numeric_limits<R>;
    return etl::cmp_greater_equal(t, limits::min()) and etl::cmp_less_equal(t, limits::max());
}

} // namespace etl

#endif // TETL_UTILITY_IN_RANGE_HPP
