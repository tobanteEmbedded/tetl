/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_SIMD_IS_VECTORIZABLE_HPP
#define TETL_SIMD_IS_VECTORIZABLE_HPP

#include "etl/_type_traits/is_arithmetic.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl::detail {
template <typename T>
inline constexpr bool is_vectorizable_v = is_arithmetic_v<T> && (!is_same_v<T, bool>);
} // namespace etl::detail

#endif // TETL_SIMD_IS_VECTORIZABLE_HPP