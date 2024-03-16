// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS1_VECTOR_ABS_SUM
#define TETL_LINALG_BLAS1_VECTOR_ABS_SUM

#include <etl/_linalg/concepts.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

template <in_vector InVec, typename Scalar>
constexpr auto vector_abs_sum(InVec v, Scalar init) noexcept -> Scalar
{
    auto sum = init;
    for (typename InVec::size_type i{0}; etl::cmp_less(i, v.extent(0)); ++i) {
        if constexpr (is_arithmetic_v<typename InVec::value_type>) {
            sum += detail::abs_if_needed(v(i));
        } else {
            sum += detail::abs_if_needed(detail::real_if_needed(v(i)));
            sum += detail::abs_if_needed(detail::imag_if_needed(v(i)));
        }
    }
    return sum;
}

template <in_vector InVec>
constexpr auto vector_abs_sum(InVec v) noexcept -> typename InVec::value_type
{
    return vector_abs_sum(v, typename InVec::value_type{});
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_VECTOR_ABS_SUM
