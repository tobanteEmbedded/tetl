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

#ifndef TAETL_VERSION_HPP
#define TAETL_VERSION_HPP

#define TAETL_REVISION_MAJOR 0
#define TAETL_REVISION_MINOR 3
#define TAETL_REVISION_PATCH 0
#define TAETL_REVISION_STRING "0.3.0"

namespace etl
{
/**
 * @brief Enumeration for the currently selected C++ standard version.
 *
 * @details Unlike the official macro __cplusplus, these values only include the
 * published year. This is to make the actual values smaller and therfore fit on
 * smaller word sized chips.
 */
enum class language_standard
{
  cpp_98 = 1998,
  cpp_11 = 2011,
  cpp_14 = 2014,
  cpp_17 = 2017,
  cpp_20 = 2020,
};

// #if __cplusplus < 201703L
// #error "C++17 or newer is required"
// #endif

#if __cplusplus == 201703L
#define TAETL_CPP_STANDARD_17
constexpr auto current_standard = language_standard::cpp_17;
#endif

#if __cplusplus > 201703L
#define TAETL_CPP_STANDARD_20
constexpr auto current_standard = language_standard::cpp_20;
#endif

/**
 * @brief Returns true, if the given standard and the currently configurated in
 * the compiler match.
 */
[[nodiscard]] constexpr auto is_language_standard(language_standard ls) -> bool
{
  return ls == current_standard;
}

[[nodiscard]] constexpr auto is_greater_language_standard(language_standard ls)
  -> bool
{
  return static_cast<long>(ls) > static_cast<long>(current_standard);
}
}  // namespace etl

#endif  // TAETL_VERSION_HPP