/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_BASE_OF_HPP
#define TETL_TYPE_TRAITS_IS_BASE_OF_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_class.hpp"

namespace etl {

namespace detail {
template <typename B>
auto test_pre_ptr_convertible(B const volatile*) -> etl::true_type;
template <typename>
auto test_pre_ptr_convertible(void const volatile*) -> etl::false_type;

template <typename, typename>
auto test_pre_is_base_of(...) -> etl::true_type;
template <typename B, typename D>
auto test_pre_is_base_of(int) -> decltype(test_pre_ptr_convertible<B>(static_cast<D*>(nullptr)));
} // namespace detail

/// \brief If Derived is derived from Base or if both are the same non-union
/// class (in both cases ignoring cv-qualification), provides the member
/// constant value equal to true. Otherwise value is false.
///
/// \details If both Base and Derived are non-union class types, and they are
/// not the same type (ignoring cv-qualification), Derived shall be a complete
/// type; otherwise the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/types/is_base_of
template <typename Base, typename Derived>
struct is_base_of
    // clang-format off
    : etl::bool_constant<
          etl::is_class_v<Base>
          && etl::is_class_v<Derived>
          && decltype(detail::test_pre_is_base_of<Base, Derived>(0))::value
    >
// clang-format on
{ };

template <typename Base, typename Derived>
inline constexpr bool is_base_of_v = is_base_of<Base, Derived>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_BASE_OF_HPP
