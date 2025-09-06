// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_COMMON_REFERENCE_HPP
#define TETL_TYPE_TRAITS_COMMON_REFERENCE_HPP

#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/basic_common_reference.hpp>
#include <etl/_type_traits/copy_cv.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/is_reference.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/remove_reference.hpp>

namespace etl {

namespace detail {

template <typename X, typename Y>
using cond_res = decltype(false ? etl::declval<X (&)()>()() : etl::declval<Y (&)()>()());

template <typename A, typename B, typename X = remove_reference_t<A>, typename Y = remove_reference_t<B>>
struct common_ref;

template <typename A, typename B>
using common_ref_t = typename common_ref<A, B>::type;

template <typename A, typename B, typename X, typename Y>
    requires requires { typename cond_res<copy_cv_t<X, Y>&, copy_cv_t<Y, X>&>; }
         and is_reference_v<cond_res<copy_cv_t<X, Y>&, copy_cv_t<Y, X>&>>
struct common_ref<A&, B&, X, Y> {
    using type = cond_res<copy_cv_t<X, Y>&, copy_cv_t<Y, X>&>;
};

} // namespace detail

/// \brief Determines the common reference type of the types T..., that is, the type to which all the
/// types in T... can be converted or bound. If such a type exists (as determined according to the
/// rules below), the member type names that type. Otherwise, there is no member type. The behavior is
/// undefined if any of the types in T... is an incomplete type other than (possibly cv-qualified)
/// void.
template <typename... T>
struct common_reference;

template <typename... T>
using common_reference_t = typename common_reference<T...>::type;

// if sizeof...(T) is zero
template <>
struct common_reference<> { };

// if sizeof...(T) is one
template <typename T0>
struct common_reference<T0> {
    using type = T0;
};

template <typename T1, typename T2>
    requires requires { typename etl::detail::common_ref_t<T1, T2>; }
         and is_reference_v<T1>
         and is_reference_v<T2>
         and is_convertible_v<add_pointer_t<T1>, add_pointer_t<etl::detail::common_ref_t<T1, T2>>>
         and is_convertible_v<add_pointer_t<T2>, add_pointer_t<etl::detail::common_ref_t<T1, T2>>>
struct common_reference<T1, T2> {
    using type = etl::detail::common_ref_t<T1, T2>;
};

} // namespace etl

#endif // TETL_TYPE_TRAITS_COMMON_REFERENCE_HPP
