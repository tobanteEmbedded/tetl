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

#ifndef TAETL_CSTDDEF_HPP
#define TAETL_CSTDDEF_HPP

#include "etl/detail/cstddef_internal.hpp"
#include "etl/detail/intrinsics.hpp"
#include "etl/detail/sfinae.hpp"

#include "etl/type_traits.hpp"

#if not defined(TAETL_MSVC) and not defined(offsetof)
/**
 * @brief Offset of member MEMBER in a struct of type TYPE.
 */
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

namespace etl
{
/**
 * @brief etl::byte is a distinct type that implements the concept of byte as
 * specified in the C++ language definition.
 *
 * @details https://en.cppreference.com/w/cpp/types/byte
 */
enum class byte : unsigned char
{
};

/**
 * @brief Equivalent to: return Integer(b); This overload only participates
 * in overload resolution if etl::is_integral_v<Integer> is true.
 */
template <typename Integer, TAETL_REQUIRES_(etl::is_integral_v<Integer>)>
[[nodiscard]] constexpr auto to_integer(etl::byte b) noexcept -> Integer
{
  return static_cast<Integer>(b);
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(b) <<
 * shift); This overload only participates in overload resolution if
 * etl::is_integral_v<Integer> is true.
 */
template <typename Integer, TAETL_REQUIRES_(etl::is_integral_v<Integer>)>
[[nodiscard]] constexpr auto operator<<(etl::byte b, Integer shift) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(b) << shift);
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(b) >>
 * shift); This overload only participates in overload resolution if
 * etl::is_integral_v<Integer> is true.
 */
template <typename Integer, TAETL_REQUIRES_(etl::is_integral_v<Integer>)>
[[nodiscard]] constexpr auto operator>>(etl::byte b, Integer shift) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(b) >> shift);
}

/**
 * @brief Equivalent to: return b = b << shift; This overload only participates
 * in overload resolution if etl::is_integral_v<Integer> is true.
 */
template <typename Integer, TAETL_REQUIRES_(etl::is_integral_v<Integer>)>
constexpr auto operator<<=(etl::byte& b, Integer shift) noexcept -> etl::byte&

{
  return b = b << shift;
}

/**
 * @brief Equivalent to: return b = b >> shift; This overload only participates
 * in overload resolution if etl::is_integral_v<Integer> is true.
 */
template <typename Integer, TAETL_REQUIRES_(etl::is_integral_v<Integer>)>
constexpr auto operator>>=(etl::byte& b, Integer shift) noexcept -> etl::byte&
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
  return etl::byte(static_cast<unsigned int>(l) | static_cast<unsigned int>(r));
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(l) &
 * static_cast<unsigned int>(r));
 */
[[nodiscard]] constexpr auto operator&(etl::byte l, etl::byte r) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(l) & static_cast<unsigned int>(r));
}

/**
 * @brief Equivalent to: return etl::byte(static_cast<unsigned int>(l) ^
 * static_cast<unsigned int>(r));
 */
[[nodiscard]] constexpr auto operator^(etl::byte l, etl::byte r) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(l) ^ static_cast<unsigned int>(r));
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

#endif  // TAETL_CSTDDEF_HPP