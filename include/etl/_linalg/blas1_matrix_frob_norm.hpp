// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS1_MATRIX_FROB_NORM_HPP
#define TETL_LINALG_BLAS1_MATRIX_FROB_NORM_HPP

#include <etl/_cmath/sqrt.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_utility/cmp.hpp>

namespace etl::linalg {

template <in_matrix InMat, typename Scalar>
[[nodiscard]] constexpr auto matrix_frob_norm(InMat a, Scalar init) -> Scalar
{
    auto result = init;
    for (typename InMat::size_type row{0}; cmp_less(row, a.extent(0)); ++row) {
        for (typename InMat::size_type col{0}; cmp_less(col, a.extent(1)); ++col) {
            result += detail::abs_if_needed(a(row, col));
        }
    }

    using etl::sqrt;
    return static_cast<Scalar>(sqrt(result));
}

template <in_matrix InMat>
[[nodiscard]] constexpr auto matrix_frob_norm(InMat a)
{
    using abs_type    = decltype(detail::abs_if_needed(declval<typename InMat::value_type>()));
    using return_type = decltype(declval<abs_type>() * declval<abs_type>());
    return matrix_frob_norm(a, return_type{});
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_MATRIX_FROB_NORM_HPP
