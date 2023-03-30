// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_TYPES_BOOL_CONSTANT_HPP
#define ETL_EXPERIMENTAL_MPL_TYPES_BOOL_CONSTANT_HPP

#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

using etl::bool_constant;
using etl::false_type;
using etl::true_type;

inline constexpr auto true_c  = true_type {};
inline constexpr auto false_c = false_type {};

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_TYPES_BOOL_CONSTANT_HPP
