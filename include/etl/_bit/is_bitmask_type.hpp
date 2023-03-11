

/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_IS_BITMASK_TYPE_HPP
#define TETL_BIT_IS_BITMASK_TYPE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/underlying_type.hpp"

namespace etl {
template <typename T>
struct is_bitmask_type : false_type { };

template <typename T>
inline constexpr auto is_bitmask_type_v = is_bitmask_type<T>::value;

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
[[nodiscard]] constexpr auto operator&(T x, T y) -> T
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(static_cast<type>(x) & static_cast<type>(y)) };
}

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
[[nodiscard]] constexpr auto operator|(T x, T y) -> T
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(static_cast<type>(x) | static_cast<type>(y)) };
}

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
[[nodiscard]] constexpr auto operator^(T x, T y) -> T
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(static_cast<type>(x) ^ static_cast<type>(y)) };
}

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
[[nodiscard]] constexpr auto operator~(T x) -> T
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(~static_cast<type>(x)) };
}

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
constexpr auto operator|=(T& x, T y) noexcept -> T const&
{
    return x = x | y;
}

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
constexpr auto operator&=(T& x, T y) noexcept -> T const&
{
    return x = x & y;
}

template <typename T, enable_if_t<is_bitmask_type_v<T>, int> = 0>
constexpr auto operator^=(T& x, T y) noexcept -> T const&
{
    return x = x ^ y;
}

} // namespace etl
#endif // TETL_BIT_IS_BITMASK_TYPE_HPP
