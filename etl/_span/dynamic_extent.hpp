/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_SPAN_DYNAMIC_EXTENT_HPP
#define TETL_SPAN_DYNAMIC_EXTENT_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief etl::dynamic_extent is a constant of type etl::size_t that is used
/// to differentiate etl::span of static and dynamic extent.
inline constexpr auto dynamic_extent = static_cast<etl::size_t>(-1);

} // namespace etl

#endif // TETL_SPAN_DYNAMIC_EXTENT_HPP