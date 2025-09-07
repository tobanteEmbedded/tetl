// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS2_MATRIX_VECTOR_PRODUCT_HPP
#define TETL_LINALG_BLAS2_MATRIX_VECTOR_PRODUCT_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/exposition.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_matrix InMat, in_vector InVec, out_vector OutVec>
constexpr auto matrix_vector_product(InMat a, InVec x, OutVec y) noexcept -> void
{
    TETL_PRECONDITION(a.extent(1) == x.extent(0));
    TETL_PRECONDITION(a.extent(0) == y.extent(0));

    using size_type = detail::common_size_type_t<InMat, InVec, OutVec>;

    for (size_type i(0); etl::cmp_less(i, a.extent(0)); ++i) {
        y(i) = typename OutVec::element_type{};
        for (size_type j(0); etl::cmp_less(j, a.extent(1)); ++j) {
            y(i) += a(i, j) * x(j);
        }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS2_MATRIX_VECTOR_PRODUCT_HPP
