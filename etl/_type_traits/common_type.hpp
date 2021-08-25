/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_COMMON_TYPE_HPP
#define TETL_TYPE_TRAITS_COMMON_TYPE_HPP

#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

/// \brief Determines the common type among all types `T...`, that is the type
/// all `T...` can be implicitly converted to. If such a type exists, the member
/// type names that type. Otherwise, there is no member type.
///
/// https://en.cppreference.com/w/cpp/types/common_type
/// \group common_type
template <typename... T>
struct common_type;

/// \exclude
template <typename T>
struct common_type<T> : common_type<T, T> {
};

namespace detail {
template <typename T1, typename T2>
using cond_t = decltype(false ? etl::declval<T1>() : etl::declval<T2>());

template <typename T1, typename T2, typename = void>
struct common_type_2_impl {
};

template <typename T1, typename T2>
struct common_type_2_impl<T1, T2, void_t<cond_t<T1, T2>>> {
    using type = etl::decay_t<cond_t<T1, T2>>;
};

template <typename AlwaysVoid, typename T1, typename T2, typename... R>
struct common_type_multi_impl {
};

template <typename T1, typename T2, typename... R>
struct common_type_multi_impl<void_t<typename common_type<T1, T2>::type>, T1,
    T2, R...> : common_type<typename common_type<T1, T2>::type, R...> {
};
} // namespace detail

/// \exclude
template <typename T1, typename T2>
struct common_type<T1, T2>
    : detail::common_type_2_impl<decay_t<T1>, decay_t<T2>> {
};

/// \exclude
template <typename T1, typename T2, typename... R>
struct common_type<T1, T2, R...>
    : detail::common_type_multi_impl<void, T1, T2, R...> {
};

/// \group common_type
template <typename... T>
using common_type_t = typename common_type<T...>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_COMMON_TYPE_HPP