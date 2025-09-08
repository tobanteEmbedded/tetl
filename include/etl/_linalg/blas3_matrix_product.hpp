// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS3_MATRIX_PRODUCT_HPP
#define TETL_LINALG_BLAS3_MATRIX_PRODUCT_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/exposition.hpp>

namespace etl::linalg {

/// Computes C = AB
/// \ingroup linalg
template <in_matrix InMat1, in_matrix InMat2, out_matrix OutMat>
constexpr auto matrix_product(InMat1 a, InMat2 b, OutMat c) -> void
{
    static_assert(detail::possibly_multipliable<InMat1, InMat2, OutMat>());
    TETL_PRECONDITION(detail::multipliable(a, b, c));

    using index_type = detail::common_index_type_t<InMat1, InMat2, OutMat>;
    using sum_type   = typename OutMat::element_type;

    for (auto i = index_type{0}; i < static_cast<index_type>(a.extent(0)); ++i) {
        for (auto j = index_type{0}; j < static_cast<index_type>(b.extent(1)); ++j) {
            auto acc = sum_type{};
            for (auto k = index_type{0}; k < static_cast<index_type>(a.extent(1)); ++k) {
                acc += a(i, k) * b(k, j);
            }
            c(i, j) = acc;
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS3_MATRIX_PRODUCT_HPP
