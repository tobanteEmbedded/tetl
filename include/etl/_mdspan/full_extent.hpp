// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_FULL_EXTENT_HPP
#define TETL_MDSPAN_FULL_EXTENT_HPP

namespace etl {

struct full_extent_t {
    explicit full_extent_t() = default;
};

inline constexpr auto full_extent = full_extent_t{};

} // namespace etl

#endif // TETL_MDSPAN_FULL_EXTENT_HPP
