// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_UTILITY_IN_RANGE_HPP
#define TETL_UTILITY_IN_RANGE_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_utility/cmp_greater_equal.hpp>
#include <etl/_utility/cmp_less_equal.hpp>

namespace etl {

/// Returns true if the value of t is in the range of values that can be
/// represented in R, that is, if t can be converted to R without data loss.
///
/// https://en.cppreference.com/w/cpp/utility/in_range
///
/// \ingroup utility
template <builtin_integer R, builtin_integer T>
[[nodiscard]] constexpr auto in_range(T t) noexcept -> bool
{
    using limits = etl::numeric_limits<R>;
    return etl::cmp_greater_equal(t, limits::min()) and etl::cmp_less_equal(t, limits::max());
}

} // namespace etl

#endif // TETL_UTILITY_IN_RANGE_HPP
