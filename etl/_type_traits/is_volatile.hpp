/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_VOLATILE_HPP
#define TETL_TYPE_TRAITS_IS_VOLATILE_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \group is_volatile
template <typename T>
struct is_volatile : false_type {
};

/// \exclude
template <typename T>
struct is_volatile<volatile T> : true_type {
};

/// \group is_volatile
template <typename T>
inline constexpr bool is_volatile_v = is_volatile<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_VOLATILE_HPP