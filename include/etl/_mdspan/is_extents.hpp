/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MDSPAN_IS_EXTENTS_HPP
#define TETL_MDSPAN_IS_EXTENTS_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

template <typename IndexType, size_t... Extents>
struct extents;

namespace detail {
template <typename T>
inline constexpr auto is_extents = false;

template <typename IndexType, size_t... Extents>
inline constexpr auto is_extents<extents<IndexType, Extents...>> = true;
} // namespace detail

} // namespace etl

#endif // TETL_MDSPAN_IS_EXTENTS_HPP
