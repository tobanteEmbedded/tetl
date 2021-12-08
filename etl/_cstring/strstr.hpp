/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRSTR_HPP
#define TETL_CSTRING_STRSTR_HPP

#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Finds the first occurrence of the byte string needle in the byte
/// string pointed to by haystack. The terminating null characters are not
/// compared.
[[nodiscard]] constexpr auto strstr(char* haystack, char* needle) noexcept -> char*
{
    return detail::strstr_impl<char>(haystack, needle);
}

/// \brief Finds the first occurrence of the byte string needle in the byte
/// string pointed to by haystack. The terminating null characters are not
/// compared.
[[nodiscard]] constexpr auto strstr(char const* haystack, char const* needle) noexcept -> char const*
{
    return detail::strstr_impl<char const>(haystack, needle);
}

} // namespace etl

#endif // TETL_CSTRING_STRSTR_HPP