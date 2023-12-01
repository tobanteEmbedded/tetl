

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_IS_BITMASK_TYPE_HPP
#define TETL_BIT_IS_BITMASK_TYPE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/underlying_type.hpp"

namespace etl {
template <typename T>
struct is_bitmask_type : false_type { };

template <typename T>
inline constexpr auto is_bitmask_type_v = is_bitmask_type<T>::value;

template <typename T>
concept bitmask_type = is_bitmask_type_v<T>;

template <bitmask_type T>
[[nodiscard]] constexpr auto operator&(T x, T y) -> T
{
    using type = underlying_type_t<T>;
    return T {static_cast<type>(static_cast<type>(x) & static_cast<type>(y))};
}

template <bitmask_type T>
[[nodiscard]] constexpr auto operator|(T x, T y) -> T
{
    using type = underlying_type_t<T>;
    return T {static_cast<type>(static_cast<type>(x) | static_cast<type>(y))};
}

template <bitmask_type T>
[[nodiscard]] constexpr auto operator^(T x, T y) -> T
{
    using type = underlying_type_t<T>;
    return T {static_cast<type>(static_cast<type>(x) ^ static_cast<type>(y))};
}

template <bitmask_type T>
[[nodiscard]] constexpr auto operator~(T x) -> T
{
    using type = underlying_type_t<T>;
    return T {static_cast<type>(~static_cast<type>(x))};
}

template <bitmask_type T>
constexpr auto operator|=(T& x, T y) noexcept -> T const&
{
    return x = x | y;
}

template <bitmask_type T>
constexpr auto operator&=(T& x, T y) noexcept -> T const&
{
    return x = x & y;
}

template <bitmask_type T>
constexpr auto operator^=(T& x, T y) noexcept -> T const&
{
    return x = x ^ y;
}

} // namespace etl
#endif // TETL_BIT_IS_BITMASK_TYPE_HPP
