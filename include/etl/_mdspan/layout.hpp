// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_LAYOUT_HPP
#define TETL_MDSPAN_LAYOUT_HPP

namespace etl {

struct layout_left {
    template <typename Extents>
    struct mapping;
};

struct layout_right {
    template <typename Extents>
    struct mapping;
};

struct layout_stride {
    template <typename Extents>
    struct mapping;
};

} // namespace etl

#endif // TETL_MDSPAN_LAYOUT_HPP
