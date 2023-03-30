// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRCHR_HPP
#define TETL_CSTRING_STRCHR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Finds the first occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strchr
[[nodiscard]] constexpr auto strchr(char const* str, int ch) -> char const*
{
    return detail::strchr_impl<char const>(str, ch);
}

/// \brief Finds the first occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strchr
[[nodiscard]] constexpr auto strchr(char* str, int ch) -> char* { return detail::strchr_impl<char>(str, ch); }

} // namespace etl

#endif // TETL_CSTRING_STRCHR_HPP
