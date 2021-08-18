

// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_BIT_IS_BITMASK_TYPE_HPP
#define TETL_BIT_IS_BITMASK_TYPE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/underlying_type.hpp"

namespace etl {
template <typename T>
struct is_bitmask_type : false_type {
};

template <typename T>
inline constexpr auto is_bitmask_type_v = is_bitmask_type<T>::value;

template <typename T>
[[nodiscard]] constexpr auto operator&(T x, T y)
    -> enable_if_t<is_bitmask_type_v<T>, T>
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(static_cast<type>(x) & static_cast<type>(y)) };
}

template <typename T>
[[nodiscard]] constexpr auto operator|(T x, T y)
    -> enable_if_t<is_bitmask_type_v<T>, T>
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(static_cast<type>(x) | static_cast<type>(y)) };
}

template <typename T>
[[nodiscard]] constexpr auto operator^(T x, T y)
    -> enable_if_t<is_bitmask_type_v<T>, T>
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(static_cast<type>(x) ^ static_cast<type>(y)) };
}

template <typename T>
[[nodiscard]] constexpr auto operator~(T x)
    -> enable_if_t<is_bitmask_type_v<T>, T>
{
    using type = underlying_type_t<T>;
    return T { static_cast<type>(~static_cast<type>(x)) };
}

template <typename T>
constexpr auto operator|=(T& x, T y) noexcept
    -> enable_if_t<is_bitmask_type_v<T>, T const&>
{
    return x = x | y;
}

template <typename T>
constexpr auto operator&=(T& x, T y) noexcept
    -> enable_if_t<is_bitmask_type_v<T>, T const&>
{
    return x = x & y;
}

template <typename T>
constexpr auto operator^=(T& x, T y) noexcept
    -> enable_if_t<is_bitmask_type_v<T>, T const&>
{
    return x = x ^ y;
}

} // namespace etl
#endif // TETL_BIT_IS_BITMASK_TYPE_HPP