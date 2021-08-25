/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_REFERENCE_WRAPPER_HPP
#define TETL_TYPE_TRAITS_IS_REFERENCE_WRAPPER_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

template <typename T>
struct reference_wrapper;

template <typename T>
struct is_reference_wrapper : false_type {
};
template <typename U>
struct is_reference_wrapper<reference_wrapper<U>> : true_type {
};

template <typename T>
inline constexpr bool is_reference_wrapper_v = is_reference_wrapper<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_REFERENCE_WRAPPER_HPP