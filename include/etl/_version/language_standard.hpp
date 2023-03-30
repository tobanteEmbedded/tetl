// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VERSION_LANGUAGE_STANDARD_HPP
#define TETL_VERSION_LANGUAGE_STANDARD_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief Enumeration for the currently selected C++ standard version. Unlike
/// the official macro `__cplusplus`, these values only include the published
/// year. This is to make the actual values smaller and therfore fit on smaller
/// word sized chips.
enum struct language_standard : unsigned char {
    cpp_17 = 17,
    cpp_20 = 20,
    cpp_23 = 23,
};

/// \brief Compares language_standards
[[nodiscard]] constexpr auto operator==(language_standard lhs, language_standard rhs) noexcept -> bool
{
    return static_cast<unsigned char>(lhs) == static_cast<unsigned char>(rhs);
}

[[nodiscard]] constexpr auto operator!=(language_standard lhs, language_standard rhs) noexcept -> bool
{
    return !(lhs == rhs);
}

[[nodiscard]] constexpr auto operator<(language_standard lhs, language_standard rhs) noexcept -> bool
{
    return static_cast<unsigned char>(lhs) < static_cast<unsigned char>(rhs);
}

[[nodiscard]] constexpr auto operator<=(language_standard lhs, language_standard rhs) noexcept -> bool
{
    return static_cast<unsigned char>(lhs) <= static_cast<unsigned char>(rhs);
}

[[nodiscard]] constexpr auto operator>(language_standard lhs, language_standard rhs) noexcept -> bool
{
    return static_cast<unsigned char>(lhs) > static_cast<unsigned char>(rhs);
}

[[nodiscard]] constexpr auto operator>=(language_standard lhs, language_standard rhs) noexcept -> bool
{
    return static_cast<unsigned char>(lhs) >= static_cast<unsigned char>(rhs);
}

#if __cplusplus > 202002L
    #define TETL_CPP_STANDARD 23
/// The currently configured C++ standard.
inline constexpr auto current_standard = language_standard::cpp_23;
#elif __cplusplus > 201703L
    #define TETL_CPP_STANDARD 20
/// The currently configured C++ standard.
inline constexpr auto current_standard = language_standard::cpp_20;
#else
    #error "Unsupported C++ language standard. TETL requires at least C++20"
#endif

} // namespace etl

#endif // TETL_VERSION_LANGUAGE_STANDARD_HPP
