// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS1_SCALE_HPP
#define TETL_LINALG_BLAS1_SCALE_HPP

#include <etl/_linalg/exposition.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <typename Scalar, inout_object InOutObj>
constexpr auto scale(Scalar alpha, InOutObj x) -> void
{
    using index_type = typename InOutObj::index_type;

    if constexpr (InOutObj::rank() == 1) {
        for (index_type i{0}; i < x.extent(0); ++i) {
            x(i) = x(i) * alpha;
        }
    } else {
        static_assert(InOutObj::rank() == 2);
        for (index_type i{0}; i < x.extent(0); ++i) {
            for (index_type j{0}; j < x.extent(1); ++j) {
                x(i, j) = x(i, j) * alpha;
            }
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_SCALE_HPP
