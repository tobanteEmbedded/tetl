// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_RANGES_SIZED_RANGE_HPP
#define TETL_RANGES_SIZED_RANGE_HPP

#include <etl/_ranges/range.hpp>
#include <etl/_ranges/size.hpp>

namespace etl::ranges {

/// \ingroup ranges
template <typename T>
concept sized_range = etl::ranges::range<T> and requires(T& t) { etl::ranges::size(t); };

} // namespace etl::ranges

#endif // TETL_RANGES_SIZED_RANGE_HPP
