// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_TYPES_INTEGRAL_CONSTANT_HPP
#define ETL_EXPERIMENTAL_MPL_TYPES_INTEGRAL_CONSTANT_HPP

#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

using etl::integral_constant;

template <int Val>
inline constexpr auto int_c = integral_constant<int, Val> {};

template <etl::size_t Size>
inline constexpr auto size_c = integral_constant<etl::size_t, Size> {};

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_TYPES_INTEGRAL_CONSTANT_HPP
