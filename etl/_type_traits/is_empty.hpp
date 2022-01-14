/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_EMPTY_HPP
#define TETL_TYPE_TRAITS_IS_EMPTY_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_class.hpp"

namespace etl {

namespace detail {
template <typename T>
struct is_empty_test_struct_1 : T {
    char dummy_data;
};

struct is_empty_test_struct_2 {
    char dummy_data;
};

template <typename T, bool = etl::is_class<T>::value>
struct is_empty_helper : etl::bool_constant<sizeof(is_empty_test_struct_1<T>) == sizeof(is_empty_test_struct_2)> {
};

template <typename T>
struct is_empty_helper<T, false> : etl::false_type {
};
} // namespace detail

/// \brief f T is an empty type (that is, a non-union class type with no
/// non-static data members other than bit-fields of size 0, no virtual
/// functions, no virtual base classes, and no non-empty base classes), provides
/// the member constant value equal to true. For any other type, value is false.
template <typename T>
struct is_empty : detail::is_empty_helper<T> {
};

template <typename T>
inline constexpr bool is_empty_v = is_empty<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_EMPTY_HPP