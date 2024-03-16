// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_EXTENT_HPP
#define TETL_TYPE_TRAITS_EXTENT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/integral_constant.hpp>

namespace etl {

/// \brief If T is an array type, provides the member constant value equal to
/// the number of elements along the Nth dimension of the array, if N is in [0,
/// rank_v<T>). For any other type, or if T is an array of unknown bound along
/// its first dimension and N is 0, value is 0.
template <typename T, unsigned N = 0>
struct extent : etl::integral_constant<etl::size_t, 0> { };

/// \exclude
template <typename T>
struct extent<T[], 0> : etl::integral_constant<etl::size_t, 0> { };

/// \exclude
template <typename T, unsigned N>
struct extent<T[], N> : extent<T, N - 1> { };

/// \exclude
template <typename T, etl::size_t I>
struct extent<T[I], 0> : integral_constant<etl::size_t, I> { };

/// \exclude
template <typename T, etl::size_t I, unsigned N>
struct extent<T[I], N> : extent<T, N - 1> { };

template <typename T, unsigned N = 0>
inline constexpr auto extent_v = static_cast<size_t>(extent<T, N>::value);

} // namespace etl

#endif // TETL_TYPE_TRAITS_EXTENT_HPP
