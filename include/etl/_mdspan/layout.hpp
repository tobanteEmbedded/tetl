/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
