// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_RANGES_ENABLE_BORROWED_RANGE_HPP
#define TETL_RANGES_ENABLE_BORROWED_RANGE_HPP

namespace etl::ranges {

/// \ingroup ranges
template <typename T>
inline constexpr bool enable_borrowed_range = false;

} // namespace etl::ranges

#endif // TETL_RANGES_ENABLE_BORROWED_RANGE_HPP
