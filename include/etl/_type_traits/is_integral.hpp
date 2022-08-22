/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_INTEGRAL_HPP
#define TETL_TYPE_TRAITS_IS_INTEGRAL_HPP

#include "etl/_type_traits/bool_constant.hpp"

#if __has_builtin(__is_integral)
namespace etl {

template <typename T>
struct is_integral : bool_constant<__is_integral(T)> {
};

template <typename T>

inline constexpr bool is_integral_v = __is_integral(T);

} // namespace etl

#else

    #include "etl/_type_traits/is_any_of.hpp"
    #include "etl/_type_traits/remove_cv.hpp"

namespace etl {
// clang-format off
template <typename T>
inline constexpr bool is_integral_v = is_any_of_v<remove_cv_t<T>,
        bool,
        char,
        signed char,
        unsigned char,
        wchar_t,
    #ifdef __cpp_char8_t
        char8_t,
    #endif
        char16_t,
        char32_t,
        short,
        unsigned short,
        int,
        unsigned int,
        long,
        unsigned long,
        long long,
        unsigned long long
    >;
// clang-format on

template <typename T>
struct is_integral : bool_constant<is_integral_v<T> > {
};

} // namespace etl

#endif

#endif // TETL_TYPE_TRAITS_IS_INTEGRAL_HPP
