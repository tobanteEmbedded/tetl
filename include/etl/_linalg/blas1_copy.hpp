// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS1_COPY_HPP
#define TETL_LINALG_BLAS1_COPY_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/exposition.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_object InObj, out_object OutObj>
    requires(InObj::rank() == OutObj::rank())
constexpr auto copy(InObj x, OutObj y) -> void
{
    TETL_PRECONDITION(x.extents() == y.extents());

    using index_type = detail::common_index_type_t<InObj, OutObj>;

    if constexpr (InObj::rank() == 1) {
        static_assert(detail::compatible_static_extents<InObj, OutObj>(0, 0));
        for (index_type i{0}; i < x.extent(0); ++i) {
            y(i) = x(i);
        }
    } else {
        static_assert(InObj::rank() == 2);
        static_assert(detail::compatible_static_extents<InObj, OutObj>(0, 0));
        static_assert(detail::compatible_static_extents<InObj, OutObj>(1, 1));

        for (index_type i{0}; i < x.extent(0); ++i) {
            for (index_type j{0}; j < x.extent(1); ++j) {
                y(i, j) = x(i, j);
            }
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_COPY_HPP
