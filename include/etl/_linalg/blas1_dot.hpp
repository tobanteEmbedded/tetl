// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
#ifndef TETL_LINALG_BLAS1_DOT_HPP
#define TETL_LINALG_BLAS1_DOT_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_linalg/exposition.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_utility/cmp_equal.hpp>

namespace etl::linalg {

/// \ingroup linalg
template <in_vector InVec1, in_vector InVec2, typename Scalar>
[[nodiscard]] constexpr auto dot(InVec1 v1, InVec2 v2, Scalar init) -> Scalar
{
    static_assert(detail::compatible_static_extents<InVec1, InVec2>(0, 0));
    TETL_PRECONDITION(etl::cmp_equal(v1.extent(0), v2.extent(0)));

    using index_type = detail::common_index_type_t<InVec1, InVec2>;
    for (index_type i{0}; i < static_cast<index_type>(v1.extent(0)); ++i) {
        init += static_cast<Scalar>(v1(i)) * static_cast<Scalar>(v2(i));
    }
    return init;
}

/// \ingroup linalg
template <in_vector InVec1, in_vector InVec2>
[[nodiscard]] constexpr auto dot(InVec1 v1, InVec2 v2)
{
    using scalar_type = decltype(declval<typename InVec1::value_type>() * declval<typename InVec2::value_type>());
    return etl::linalg::dot(v1, v2, scalar_type{});
}

} // namespace etl::linalg

#endif // TETL_LINALG_BLAS1_DOT_HPP
