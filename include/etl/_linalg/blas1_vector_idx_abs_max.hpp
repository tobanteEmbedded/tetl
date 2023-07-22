// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_BLAS1_VECTOR_IDX_ABS_MAX_HPP
#define TETL_LINALG_BLAS1_VECTOR_IDX_ABS_MAX_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_utility/cmp.hpp>

namespace etl::linalg {

template <detail::in_vector InVec>
constexpr auto idx_abs_max(InVec v) -> typename InVec::size_type
{
    auto get_value = [](auto val) {
        if constexpr (is_arithmetic_v<typename InVec::value_type>) {
            return detail::abs_if_needed(val);
        } else {
            auto const re = detail::abs_if_needed(detail::real_if_needed(val));
            auto const im = detail::abs_if_needed(detail::imag_if_needed(val));
            return re + im;
        }
    };

    auto idx   = numeric_limits<typename InVec::size_type>::max();
    auto max_v = numeric_limits<decltype(get_value(v(0)))>::min();

    for (typename InVec::size_type i { 0 }; cmp_less(i, v.extent(0)); ++i) {
        if (auto const val = get_value(v(i)); val > max_v) {
            idx   = i;
            max_v = val;
        }
    }

    return idx;
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_VECTOR_IDX_ABS_MAX_HPP
