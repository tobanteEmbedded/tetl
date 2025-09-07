// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS1_COPY_HPP
#define TETL_LINALG_BLAS1_COPY_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/exposition.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_object InObj, out_object OutObj>
    requires(InObj::rank() == OutObj::rank())
constexpr auto copy(InObj x, OutObj y) -> void
{
    TETL_PRECONDITION(x.extents() == y.extents());

    using size_type = detail::common_size_type_t<InObj, OutObj>;

    if constexpr (InObj::rank() == 1) {
        for (size_type i{0}; etl::cmp_less(i, x.extent(0)); ++i) {
            y(i) = x(i);
        }
    } else {
        static_assert(InObj::rank() == 2);
        for (size_type i{0}; etl::cmp_less(i, x.extent(0)); ++i) {
            for (size_type j{0}; etl::cmp_less(j, x.extent(1)); ++j) {
                y(i, j) = x(i, j);
            }
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_COPY_HPP
