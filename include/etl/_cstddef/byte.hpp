/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDDEF_BYTE_HPP
#define TETL_CSTDDEF_BYTE_HPP

#include <etl/_concepts/integral.hpp>

namespace etl {
/// \brief etl::byte is a distinct type that implements the concept of byte as
/// specified in the C++ language definition.
///
/// \details Like char and unsigned char, it can be used to access raw memory
/// occupied by other objects, but unlike those types, it is not a character
/// type and is not an arithmetic type. A byte is only a collection of bits, and
/// the only operators defined for it are the bitwise ones.
///
/// https://en.cppreference.com/w/cpp/types/byte
enum struct byte : unsigned char {};

/// \brief Equivalent to: `return Int(b);`
template <integral Int>
[[nodiscard]] constexpr auto to_integer(etl::byte b) noexcept -> Int
{
    return static_cast<Int>(b);
}

/// \brief Equivalent to: `return etl::byte(static_cast<unsigned int>(b) <<`
/// shift)
template <integral Int>
[[nodiscard]] constexpr auto operator<<(etl::byte b, Int shift) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(b) << shift);
}

/// \brief Equivalent to: `return etl::byte(static_cast<unsigned int>(b) >>`
/// shift)
template <integral Int>
[[nodiscard]] constexpr auto operator>>(etl::byte b, Int shift) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(b) >> shift);
}

/// \brief Equivalent to: `return b = b << shift;`
template <integral Int>
constexpr auto operator<<=(etl::byte& b, Int shift) noexcept -> etl::byte&

{
    return b = b << shift;
}

/// \brief Equivalent to: `return b = b >> shift;`
template <integral Int>
constexpr auto operator>>=(etl::byte& b, Int shift) noexcept -> etl::byte&
{
    return b = b >> shift;
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(l) |
/// static_cast<unsigned int>(r));`
[[nodiscard]] constexpr auto operator|(etl::byte l, etl::byte r) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(l) | static_cast<unsigned int>(r));
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(l) &
/// static_cast<unsigned int>(r));`
[[nodiscard]] constexpr auto operator&(etl::byte l, etl::byte r) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(l) & static_cast<unsigned int>(r));
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(l) ^
/// static_cast<unsigned int>(r));`
[[nodiscard]] constexpr auto operator^(etl::byte l, etl::byte r) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(l) ^ static_cast<unsigned int>(r));
}

/// \brief Equivalent to: `return byte(~static_cast<unsigned int>(b));`
[[nodiscard]] constexpr auto operator~(etl::byte b) noexcept -> etl::byte
{
    return etl::byte(~static_cast<unsigned int>(b));
}

/// \brief Equivalent to: `return l = l | r;`
constexpr auto operator|=(etl::byte& l, etl::byte r) noexcept -> etl::byte& { return l = l | r; }

/// \brief Equivalent to: `return l = l & r;`
constexpr auto operator&=(etl::byte& l, etl::byte r) noexcept -> etl::byte& { return l = l & r; }

/// \brief Equivalent to: `return l = l ^ r;`
constexpr auto operator^=(etl::byte& l, etl::byte r) noexcept -> etl::byte& { return l = l ^ r; }

} // namespace etl

#endif // TETL_CSTDDEF_BYTE_HPP
