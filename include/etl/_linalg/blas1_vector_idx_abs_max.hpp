// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS1_VECTOR_IDX_ABS_MAX_HPP
#define TETL_LINALG_BLAS1_VECTOR_IDX_ABS_MAX_HPP

#include <etl/_limits/numeric_limits.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_vector InVec>
constexpr auto idx_abs_max(InVec v) -> typename InVec::size_type
{
    constexpr auto getValue = [](typename InVec::value_type const& val) {
        if constexpr (is_arithmetic_v<typename InVec::value_type>) {
            return detail::abs_if_needed(val);
        } else {
            auto const re = detail::abs_if_needed(detail::real_if_needed(val));
            auto const im = detail::abs_if_needed(detail::imag_if_needed(val));
            return re + im;
        }
    };

    auto idx  = numeric_limits<typename InVec::size_type>::max();
    auto maxV = numeric_limits<decltype(getValue(v(0)))>::min();

    for (typename InVec::size_type i{0}; etl::cmp_less(i, v.extent(0)); ++i) {
        if (auto const val = getValue(v(i)); val > maxV) {
            idx  = i;
            maxV = val;
        }
    }

    return idx;
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_VECTOR_IDX_ABS_MAX_HPP
