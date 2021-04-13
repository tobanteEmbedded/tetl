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

#ifndef TETL_VERSION_HPP
#define TETL_VERSION_HPP

#include "etl/detail/intrinsics.hpp"

/// The major release version
#define TETL_VERSION_MAJOR 0
/// The minor release version
#define TETL_VERSION_MINOR 4
/// The patch release version
#define TETL_VERSION_PATCH 0
/// The library version as a string literal
#define TETL_VERSION_STRING "0.4.0"

namespace etl
{
/// \brief Enumeration for the currently selected C++ standard version. Unlike
/// the official macro `__cplusplus`, these values only include the published
/// year. This is to make the actual values smaller and therfore fit on smaller
/// word sized chips.
enum class language_standard : unsigned char
{
  cpp_17 = 17,
  cpp_20 = 20,
  cpp_23 = 23,
};

#if __cplusplus == 201703L
#define TETL_CPP_STANDARD_17
/// The currently configured C++ standard.
constexpr auto current_standard = language_standard::cpp_17;
#endif

#if __cplusplus > 201703L
#define TETL_CPP_STANDARD_20
/// The currently configured C++ standard.
constexpr auto current_standard = language_standard::cpp_20;
#endif

/// \brief Compares language_standards
/// \group language_standard_compare
/// \module Utility
[[nodiscard]] constexpr auto operator==(language_standard lhs,
                                        language_standard rhs) noexcept -> bool
{
  return static_cast<unsigned char>(lhs) == static_cast<unsigned char>(rhs);
}

/// \group language_standard_compare
[[nodiscard]] constexpr auto operator!=(language_standard lhs,
                                        language_standard rhs) noexcept -> bool
{
  return !(lhs == rhs);
}

/// \group language_standard_compare
[[nodiscard]] constexpr auto operator<(language_standard lhs,
                                       language_standard rhs) noexcept -> bool
{
  return static_cast<unsigned char>(lhs) < static_cast<unsigned char>(rhs);
}

/// \group language_standard_compare
[[nodiscard]] constexpr auto operator<=(language_standard lhs,
                                        language_standard rhs) noexcept -> bool
{
  return static_cast<unsigned char>(lhs) <= static_cast<unsigned char>(rhs);
}

/// \group language_standard_compare
[[nodiscard]] constexpr auto operator>(language_standard lhs,
                                       language_standard rhs) noexcept -> bool
{
  return static_cast<unsigned char>(lhs) > static_cast<unsigned char>(rhs);
}

/// \group language_standard_compare
[[nodiscard]] constexpr auto operator>=(language_standard lhs,
                                        language_standard rhs) noexcept -> bool
{
  return static_cast<unsigned char>(lhs) >= static_cast<unsigned char>(rhs);
}

}  // namespace etl

#endif  // TETL_VERSION_HPP