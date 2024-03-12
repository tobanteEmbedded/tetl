

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_PLACEHOLDER_HPP
#define TETL_FUNCTIONAL_PLACEHOLDER_HPP

#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

template <typename T>
struct is_placeholder : integral_constant<int, 0> { };

namespace detail {
template <int N>
struct placeholder_type {
    static_assert(N > 0, "invalid placeholder index");
};

} // namespace detail

template <int N>
struct is_placeholder<detail::placeholder_type<N>> : integral_constant<int, N> { };

template <typename T>
struct is_placeholder<T const> : is_placeholder<T>::type { };

template <typename T>
struct is_placeholder<T volatile> : is_placeholder<T>::type { };

template <typename T>
struct is_placeholder<T const volatile> : is_placeholder<T>::type { };

template <typename T>
inline constexpr int is_placeholder_v = is_placeholder<T>::value;

namespace placeholders {
inline constexpr auto _1  = detail::placeholder_type<1>{};
inline constexpr auto _2  = detail::placeholder_type<2>{};
inline constexpr auto _3  = detail::placeholder_type<3>{};
inline constexpr auto _4  = detail::placeholder_type<4>{};
inline constexpr auto _5  = detail::placeholder_type<5>{};
inline constexpr auto _6  = detail::placeholder_type<6>{};
inline constexpr auto _7  = detail::placeholder_type<7>{};
inline constexpr auto _8  = detail::placeholder_type<8>{};
inline constexpr auto _9  = detail::placeholder_type<9>{};
inline constexpr auto _10 = detail::placeholder_type<10>{};
inline constexpr auto _11 = detail::placeholder_type<11>{};
inline constexpr auto _12 = detail::placeholder_type<12>{};
inline constexpr auto _13 = detail::placeholder_type<13>{};
inline constexpr auto _14 = detail::placeholder_type<14>{};
inline constexpr auto _15 = detail::placeholder_type<15>{};
inline constexpr auto _16 = detail::placeholder_type<16>{};
inline constexpr auto _17 = detail::placeholder_type<17>{};
inline constexpr auto _18 = detail::placeholder_type<18>{};
inline constexpr auto _19 = detail::placeholder_type<19>{};
inline constexpr auto _20 = detail::placeholder_type<20>{};
inline constexpr auto _21 = detail::placeholder_type<21>{};
inline constexpr auto _22 = detail::placeholder_type<22>{};
inline constexpr auto _23 = detail::placeholder_type<23>{};
inline constexpr auto _24 = detail::placeholder_type<24>{};
inline constexpr auto _25 = detail::placeholder_type<25>{};
inline constexpr auto _26 = detail::placeholder_type<26>{};
inline constexpr auto _27 = detail::placeholder_type<27>{};
inline constexpr auto _28 = detail::placeholder_type<28>{};
inline constexpr auto _29 = detail::placeholder_type<29>{};
inline constexpr auto _30 = detail::placeholder_type<30>{};
inline constexpr auto _31 = detail::placeholder_type<31>{};
inline constexpr auto _32 = detail::placeholder_type<32>{};
} // namespace placeholders

} // namespace etl

#endif // TETL_FUNCTIONAL_PLACEHOLDER_HPP
