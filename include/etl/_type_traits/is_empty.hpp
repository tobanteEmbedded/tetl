// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_EMPTY_HPP
#define TETL_TYPE_TRAITS_IS_EMPTY_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_class.hpp>

namespace etl {

namespace detail {

template <typename T>
struct is_empty_tester_1 : T {
    char dummy_data;
};

struct is_empty_tester_2 {
    char dummy_data;
};

template <typename T>
struct is_empty : etl::false_type { };

template <typename T>
    requires etl::is_class_v<T>
struct is_empty<T> : etl::bool_constant<sizeof(is_empty_tester_1<T>) == sizeof(is_empty_tester_2)> { };

} // namespace detail

/// \brief f T is an empty type (that is, a non-union class type with no
/// non-static data members other than bit-fields of size 0, no virtual
/// functions, no virtual base classes, and no non-empty base classes), provides
/// the member constant value equal to true. For any other type, value is false.
template <typename T>
struct is_empty : etl::detail::is_empty<T> { };

template <typename T>
inline constexpr bool is_empty_v = is_empty<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_EMPTY_HPP
