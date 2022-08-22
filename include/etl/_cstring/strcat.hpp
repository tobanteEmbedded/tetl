/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRCAT_HPP
#define TETL_CSTRING_STRCAT_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Appends a copy of the character string pointed to by src to the end
/// of the character string pointed to by dest. The character src[0] replaces
/// the null terminator at the end of dest. The resulting byte string is
/// null-terminated.
///
/// \details The behavior is undefined if the destination array is not large
/// enough for the contents of both src and dest and the terminating null
/// character. The behavior is undefined if the strings overlap.
constexpr auto strcat(char* dest, char const* src) -> char*
{
    return detail::strcat_impl<char, etl::size_t>(dest, src);
}

} // namespace etl

#endif // TETL_CSTRING_STRCAT_HPP
