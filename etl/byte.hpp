/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_BYTE_HPP
#define TAETL_BYTE_HPP

#include "definitions.hpp"
#include "type_traits.hpp"

namespace etl
{
enum class byte : uint8_t
{
};

/**
 * @brief Equivalent to: return Integer(b); This overload only participates
 * in overload resolution if etl::is_integral_v<Integer> is true.
 */
template <typename Integer>
[[nodiscard]] constexpr auto to_integer(etl::byte b) noexcept
    -> etl::enable_if_t<etl::is_integral_v<Integer>, Integer>
{
    return static_cast<Integer>(b);
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(b) <<
 * shift); This overload only participates in overload resolution if
 * etl::is_integral_v<Integer> is true.
 */
template <class Integer>
[[nodiscard]] constexpr auto operator<<(etl::byte b, Integer shift) noexcept
    -> etl::enable_if_t<etl::is_integral_v<Integer>, etl::byte>
{
    return etl::byte(static_cast<unsigned int>(b) << shift);
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(b) >>
 * shift); This overload only participates in overload resolution if
 * etl::is_integral_v<Integer> is true.
 */
template <class Integer>
[[nodiscard]] constexpr auto operator>>(etl::byte b, Integer shift) noexcept
    -> etl::enable_if_t<etl::is_integral_v<Integer>, etl::byte>
{
    return etl::byte(static_cast<unsigned int>(b) >> shift);
}

/**
 * @brief Equivalent to: return b = b << shift; This overload only participates
 * in overload resolution if etl::is_integral_v<Integer> is true.
 */
template <class Integer>
constexpr auto operator<<=(etl::byte& b, Integer shift) noexcept
    -> etl::enable_if_t<etl::is_integral_v<Integer>, etl::byte&>

{
    return b = b << shift;
}

/**
 * @brief Equivalent to: return b = b >> shift; This overload only participates
 * in overload resolution if etl::is_integral_v<Integer> is true.
 */
template <class Integer>
constexpr auto operator>>=(etl::byte& b, Integer shift) noexcept
    -> etl::enable_if_t<etl::is_integral_v<Integer>, etl::byte&>
{
    return b = b >> shift;
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(l) |
 * static_cast<unsigned int>(r));
 */
[[nodiscard]] constexpr auto operator|(etl::byte l, etl::byte r) noexcept
    -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(l)
                     | static_cast<unsigned int>(r));
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(l) &
 * static_cast<unsigned int>(r));
 */
[[nodiscard]] constexpr auto operator&(etl::byte l, etl::byte r) noexcept
    -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(l)
                     & static_cast<unsigned int>(r));
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(l) ^
 * static_cast<unsigned int>(r));
 */
[[nodiscard]] constexpr auto operator^(etl::byte l, etl::byte r) noexcept
    -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(l)
                     ^ static_cast<unsigned int>(r));
}

/**
 * @brief Equivalent to: return etl::byte(~static_cast<unsigned int>(b));
 */
[[nodiscard]] constexpr auto operator~(etl::byte b) noexcept -> etl::byte
{
    return etl::byte(~static_cast<unsigned int>(b));
}

/**
 * @brief Equivalent to: return l = l | r;
 */
constexpr auto operator|=(etl::byte& l, etl::byte r) noexcept -> etl::byte&
{
    return l = l | r;
}

/**
 * @brief Equivalent to: return l = l & r;
 */
constexpr auto operator&=(etl::byte& l, etl::byte r) noexcept -> etl::byte&
{
    return l = l & r;
}

/**
 * @brief Equivalent to: return l = l ^ r;
 */
constexpr auto operator^=(etl::byte& l, etl::byte r) noexcept -> etl::byte&
{
    return l = l ^ r;
}

}  // namespace etl

#endif  // TAETL_BYTE_HPP