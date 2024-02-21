// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS2_MATRIX_VECTOR_PRODUCT_HPP
#define TETL_LINALG_BLAS2_MATRIX_VECTOR_PRODUCT_HPP

#include <etl/_linalg/concepts.hpp>
#include <etl/_utility/cmp.hpp>

namespace etl::linalg {

template <in_matrix InMat, in_vector InVec, out_vector OutVec>
constexpr auto matrix_vector_product(InMat a, InVec x, OutVec y) noexcept -> void
{
    // PRECONDITION(A.extent(1) == x.extent(0));
    // PRECONDITION(A.extent(0) == y.extent(0));

    using size_type = detail::common_size_type_t<InMat, InVec, OutVec>;

    for (size_type i(0); cmp_less(i, a.extent(0)); ++i) {
        y(i) = typename OutVec::element_type {};
        for (size_type j(0); cmp_less(j, a.extent(1)); ++j) { y(i) += a(i, j) * x(j); }
    }
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS2_MATRIX_VECTOR_PRODUCT_HPP
