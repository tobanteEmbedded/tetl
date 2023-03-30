// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SPAN_DYNAMIC_EXTENT_HPP
#define TETL_SPAN_DYNAMIC_EXTENT_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

/// \brief etl::dynamic_extent is a constant of type etl::size_t that is used
/// to differentiate etl::span of static and dynamic extent.
inline constexpr auto dynamic_extent = numeric_limits<etl::size_t>::max();

} // namespace etl

#endif // TETL_SPAN_DYNAMIC_EXTENT_HPP
