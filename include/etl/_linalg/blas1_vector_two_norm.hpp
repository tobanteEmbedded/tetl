// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_BLAS1_VECTOR_TWO_NORM_HPP
#define TETL_LINALG_BLAS1_VECTOR_TWO_NORM_HPP

#include <etl/_cmath/sqrt.hpp>
#include <etl/_linalg/exposition.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_vector InVec, typename Scalar>
constexpr auto vector_two_norm(InVec v, Scalar init) noexcept -> Scalar
{
    auto sum = init;
    for (typename InVec::size_type i{0}; etl::cmp_less(i, v.extent(0)); ++i) {
        auto const val    = detail::abs_if_needed(v(i));
        auto const square = val * val;
        sum += square;
    }

    using etl::sqrt;
    return static_cast<Scalar>(sqrt(sum));
}

/// \ingroup linalg
template <in_vector InVec>
constexpr auto vector_two_norm(InVec v) noexcept -> typename InVec::value_type
{
    using abs_type   = decltype(detail::abs_if_needed(declval<typename InVec::value_type>()));
    using value_type = decltype(declval<abs_type>() * declval<abs_type>());
    return vector_two_norm(v, value_type{});
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_VECTOR_TWO_NORM_HPP
