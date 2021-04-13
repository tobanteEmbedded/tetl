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

#ifndef TETL_CSTDDEF_HPP
#define TETL_CSTDDEF_HPP

#include "etl/detail/cstddef_internal.hpp"
#include "etl/detail/intrinsics.hpp"
#include "etl/detail/sfinae.hpp"

#include "etl/type_traits.hpp"

namespace etl
{
/// \brief etl::byte is a distinct type that implements the concept of byte as
/// specified in the C++ language definition.
/// \details Like char and unsigned char, it can be used to access raw memory
/// occupied by other objects, but unlike those types, it is not a character
/// type and is not an arithmetic type. A byte is only a collection of bits, and
/// the only operators defined for it are the bitwise ones. \notes
/// [cppreference.com/w/cpp/types/byte](https://en.cppreference.com/w/cpp/types/byte)
enum struct byte : unsigned char
{
};

/// \brief Equivalent to: `return Int(b);`
/// \requires etl::is_integral_v<Int>
template <typename Int>
[[nodiscard]] constexpr auto to_integer(etl::byte b) noexcept
  -> enable_if_t<is_integral_v<Int>, Int>
{
  return static_cast<Int>(b);
}

/// \brief Equivalent to: `return etl::byte(static_cast<unsigned int>(b) <<`
/// shift)
/// \requires etl::is_integral_v<Int>
template <typename Int>
[[nodiscard]] constexpr auto operator<<(etl::byte b, Int shift) noexcept
  -> enable_if_t<is_integral_v<Int>, etl::byte>
{
  return etl::byte(static_cast<unsigned int>(b) << shift);
}

/// \brief Equivalent to: `return etl::byte(static_cast<unsigned int>(b) >>`
/// shift)
/// \requires etl::is_integral_v<Int>
template <typename Int>
[[nodiscard]] constexpr auto operator>>(etl::byte b, Int shift) noexcept
  -> enable_if_t<is_integral_v<Int>, etl::byte>
{
  return etl::byte(static_cast<unsigned int>(b) >> shift);
}

/// \brief Equivalent to: `return b = b << shift;`
/// \requires etl::is_integral_v<Int>
template <typename Int>
constexpr auto operator<<=(etl::byte& b, Int shift) noexcept
  -> enable_if_t<is_integral_v<Int>, etl::byte&>

{
  return b = b << shift;
}

/// \brief Equivalent to: `return b = b >> shift;`
/// \requires etl::is_integral_v<Int>
template <typename Int>
constexpr auto operator>>=(etl::byte& b, Int shift) noexcept
  -> enable_if_t<is_integral_v<Int>, etl::byte&>
{
  return b = b >> shift;
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(l) |
/// static_cast<unsigned int>(r));`
[[nodiscard]] constexpr auto operator|(etl::byte l, etl::byte r) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(l) | static_cast<unsigned int>(r));
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(l) &
/// static_cast<unsigned int>(r));`
[[nodiscard]] constexpr auto operator&(etl::byte l, etl::byte r) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(l) & static_cast<unsigned int>(r));
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(l) ^
/// static_cast<unsigned int>(r));`
[[nodiscard]] constexpr auto operator^(etl::byte l, etl::byte r) noexcept
  -> etl::byte
{
  return etl::byte(static_cast<unsigned int>(l) ^ static_cast<unsigned int>(r));
}

/// \brief Equivalent to: `return byte(~static_cast<unsigned int>(b));`
[[nodiscard]] constexpr auto operator~(etl::byte b) noexcept -> etl::byte
{
  return etl::byte(~static_cast<unsigned int>(b));
}

/// \brief Equivalent to: `return l = l | r;`
constexpr auto operator|=(etl::byte& l, etl::byte r) noexcept -> etl::byte&
{
  return l = l | r;
}

/// \brief Equivalent to: `return l = l & r;`
constexpr auto operator&=(etl::byte& l, etl::byte r) noexcept -> etl::byte&
{
  return l = l & r;
}

/// \brief Equivalent to: `return l = l ^ r;`
constexpr auto operator^=(etl::byte& l, etl::byte r) noexcept -> etl::byte&
{
  return l = l ^ r;
}

}  // namespace etl

#endif  // TETL_CSTDDEF_HPP