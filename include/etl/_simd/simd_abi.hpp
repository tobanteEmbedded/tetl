// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SIMD_SIMD_ABI_HPP
#define TETL_SIMD_SIMD_ABI_HPP

#include "etl/_config/all.hpp"

namespace etl::simd_abi {

namespace detail {
struct simd_abi_scaler_tag { };

template <int N>
struct simd_abi_fixed_size_tag { };

template <typename T>
struct simd_abi_compatible_tag { };

template <typename T>
struct simd_abi_native_tag { };
} // namespace detail

using scalar = detail::simd_abi_scaler_tag;

template <int N>
using fixed_size = detail::simd_abi_fixed_size_tag<N>;

template <typename T>
inline constexpr int max_fixed_size = 32;

template <typename T>
using compatible = detail::simd_abi_compatible_tag<T>;

template <typename T>
using native = detail::simd_abi_native_tag<T>;

// TODO(tobi)
// template <typename T, size_t N, typename... Abis>
// struct deduce {
//     using type = /* see below */;
// };

// template <typename T, size_t N, typename... Abis>
// using deduce_t = typename deduce<T, N, Abis...>::type;

} // namespace etl::simd_abi

#endif // TETL_SIMD_SIMD_ABI_HPP
