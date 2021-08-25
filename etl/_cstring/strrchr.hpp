/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRRCHR_HPP
#define TETL_CSTRING_STRRCHR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Finds the last occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strrchr
///
/// \module Strings
[[nodiscard]] constexpr auto strrchr(char const* str, int ch) -> char const*
{
    return detail::strrchr_impl<char const, etl::size_t>(str, ch);
}

/// \brief Finds the last occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strrchr
///
/// \module Strings
[[nodiscard]] constexpr auto strrchr(char* str, int ch) -> char*
{
    return detail::strrchr_impl<char, etl::size_t>(str, ch);
}

} // namespace etl

#endif // TETL_CSTRING_STRRCHR_HPP