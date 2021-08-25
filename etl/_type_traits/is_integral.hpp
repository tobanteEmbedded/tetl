/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_INTEGRAL_HPP
#define TETL_TYPE_TRAITS_IS_INTEGRAL_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

namespace detail {

// clang-format off
template <typename> struct is_integral_impl                     : etl::false_type {};

template <>         struct is_integral_impl<bool>               : etl::true_type {};

template <>         struct is_integral_impl<char>               : etl::true_type {};
template <>         struct is_integral_impl<signed char>        : etl::true_type {};
template <>         struct is_integral_impl<unsigned char>      : etl::true_type {};

template <>         struct is_integral_impl<char16_t>           : etl::true_type {};
template <>         struct is_integral_impl<char32_t>           : etl::true_type {};

template <>         struct is_integral_impl<short>              : etl::true_type {};
template <>         struct is_integral_impl<unsigned short>     : etl::true_type {};

template <>         struct is_integral_impl<int>                : etl::true_type {};
template <>         struct is_integral_impl<unsigned int>       : etl::true_type {};

template <>         struct is_integral_impl<long>               : etl::true_type {};
template <>         struct is_integral_impl<unsigned long>      : etl::true_type {};

template <>         struct is_integral_impl<long long>          : etl::true_type {};
template <>         struct is_integral_impl<unsigned long long> : etl::true_type {};
// clang-format on

} // namespace detail

/// \group is_integral
template <typename Type>
struct is_integral : detail::is_integral_impl<remove_cv_t<Type>>::type {
};

/// \group is_integral
template <typename T>
inline constexpr bool is_integral_v = is_integral<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_INTEGRAL_HPP