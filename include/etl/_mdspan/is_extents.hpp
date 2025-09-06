// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_MDSPAN_IS_EXTENTS_HPP
#define TETL_MDSPAN_IS_EXTENTS_HPP

#include <etl/_cstddef/size_t.hpp>

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
