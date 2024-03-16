// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_VOLATILE_HPP
#define TETL_TYPE_TRAITS_IS_VOLATILE_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

template <typename T>
struct is_volatile : etl::false_type { };

/// \exclude
template <typename T>
struct is_volatile<T volatile> : etl::true_type { };

template <typename T>
inline constexpr bool is_volatile_v = etl::is_volatile<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_VOLATILE_HPP
