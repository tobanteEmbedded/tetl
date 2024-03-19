// SPDX-License-Identifier: BSL-1.0

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
enum struct TETL_MAY_ALIAS byte : unsigned char {
};

/// \brief Equivalent to: `return Int(b);`
template <etl::integral Int>
[[nodiscard]] constexpr auto to_integer(etl::byte b) noexcept -> Int
{
    return static_cast<Int>(b);
}

/// \brief Equivalent to: `return etl::byte(static_cast<unsigned int>(b) <<  shift);`
template <etl::integral Int>
[[nodiscard]] constexpr auto operator<<(etl::byte b, Int shift) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(b) << shift);
}

/// \brief Equivalent to: `return etl::byte(static_cast<unsigned int>(b) >> shift);`
template <etl::integral Int>
[[nodiscard]] constexpr auto operator>>(etl::byte b, Int shift) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(b) >> shift);
}

/// \brief Equivalent to: `return b = b << shift;`
template <etl::integral Int>
constexpr auto operator<<=(etl::byte& b, Int shift) noexcept -> etl::byte&

{
    return b = b << shift;
}

/// \brief Equivalent to: `return b = b >> shift;`
template <etl::integral Int>
constexpr auto operator>>=(etl::byte& b, Int shift) noexcept -> etl::byte&
{
    return b = b >> shift;
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(lhs) | static_cast<unsigned int>(rhs));`
[[nodiscard]] constexpr auto operator|(etl::byte lhs, etl::byte rhs) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(lhs) | static_cast<unsigned int>(rhs));
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(lhs) & static_cast<unsigned int>(rhs));`
[[nodiscard]] constexpr auto operator&(etl::byte lhs, etl::byte rhs) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(lhs) & static_cast<unsigned int>(rhs));
}

/// \brief Equivalent to: `return byte(static_cast<unsigned int>(lhs) ^ static_cast<unsigned int>(rhs));`
[[nodiscard]] constexpr auto operator^(etl::byte lhs, etl::byte rhs) noexcept -> etl::byte
{
    return etl::byte(static_cast<unsigned int>(lhs) ^ static_cast<unsigned int>(rhs));
}

/// \brief Equivalent to: `return byte(~static_cast<unsigned int>(b));`
[[nodiscard]] constexpr auto operator~(etl::byte b) noexcept -> etl::byte
{
    return etl::byte(~static_cast<unsigned int>(b));
}

/// \brief Equivalent to: `return lhs = lhs | rhs;`
constexpr auto operator|=(etl::byte& lhs, etl::byte rhs) noexcept -> etl::byte& { return lhs = lhs | rhs; }

/// \brief Equivalent to: `return lhs = lhs & rhs;`
constexpr auto operator&=(etl::byte& lhs, etl::byte rhs) noexcept -> etl::byte& { return lhs = lhs & rhs; }

/// \brief Equivalent to: `return lhs = lhs ^ rhs;`
constexpr auto operator^=(etl::byte& lhs, etl::byte rhs) noexcept -> etl::byte& { return lhs = lhs ^ rhs; }

} // namespace etl

#endif // TETL_CSTDDEF_BYTE_HPP
