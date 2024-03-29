// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS1_SCALE_HPP
#define TETL_LINALG_BLAS1_SCALE_HPP

#include <etl/_linalg/concepts.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <typename Scalar, inout_object InOutObj>
constexpr auto scale(Scalar alpha, InOutObj x) -> void
{
    using size_type = typename InOutObj::size_type;

    if constexpr (InOutObj::rank() == 1) {
        for (size_type i{0}; etl::cmp_less(i, x.extent(0)); ++i) {
            x(i) = x(i) * alpha;
        }
    } else {
        static_assert(InOutObj::rank() == 2);
        for (size_type i{0}; etl::cmp_less(i, x.extent(0)); ++i) {
            for (size_type j{0}; etl::cmp_less(j, x.extent(1)); ++j) {
                x(i, j) = x(i, j) * alpha;
            }
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_SCALE_HPP
