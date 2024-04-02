// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_DISABLE_SIZED_RANGE_HPP
#define TETL_RANGES_DISABLE_SIZED_RANGE_HPP

namespace etl::ranges {

/// \ingroup ranges
template <typename>
inline constexpr auto disable_sized_range = false;

} // namespace etl::ranges

#endif // TETL_RANGES_DISABLE_SIZED_RANGE_HPP
