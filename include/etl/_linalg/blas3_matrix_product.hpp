// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS3_MATRIX_PRODUCT_HPP
#define TETL_LINALG_BLAS3_MATRIX_PRODUCT_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/exposition.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// Computes C = AB
/// \ingroup linalg
template <in_matrix InMat1, in_matrix InMat2, out_matrix OutMat>
    requires(detail::possibly_multipliable<InMat1, InMat2, OutMat>())
constexpr auto matrix_product(InMat1 A, InMat2 B, OutMat C) -> void
{
    TETL_PRECONDITION(detail::multipliable(A, B, C));

    using SumT = typename OutMat::element_type;

    auto const M = A.extent(0);
    auto const K = A.extent(1);
    auto const N = B.extent(1);

    for (auto i = 0zu; etl::cmp_less(i, M); ++i) {
        for (auto j = 0zu; etl::cmp_less(j, N); ++j) {
            auto acc = SumT{};
            for (auto k = 0zu; etl::cmp_less(k, K); ++k) {
                acc += A(i, k) * B(k, j);
            }
            C(i, j) = acc;
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS3_MATRIX_PRODUCT_HPP
