// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MDSPAN_FULL_EXTENT_HPP
#define TETL_MDSPAN_FULL_EXTENT_HPP

namespace etl {

/// \ingroup mdspan
struct full_extent_t {
    explicit full_extent_t() = default;
};

/// \relates full_extent_t
/// \ingroup mdspan
inline constexpr auto full_extent = full_extent_t{};

} // namespace etl

#endif // TETL_MDSPAN_FULL_EXTENT_HPP
