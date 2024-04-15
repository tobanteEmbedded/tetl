// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRCAT_HPP
#define TETL_CSTRING_STRCAT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Appends a copy of the character string pointed to by src to the end
/// of the character string pointed to by dest. The character src[0] replaces
/// the null terminator at the end of dest. The resulting byte string is
/// null-terminated.
///
/// The behavior is undefined if the destination array is not large
/// enough for the contents of both src and dest and the terminating null
/// character. The behavior is undefined if the strings overlap.
///
/// \ingroup cstring
constexpr auto strcat(char* dest, char const* src) noexcept -> char*
{
    return etl::cstr::strcat<char, etl::size_t>(dest, src);
}

} // namespace etl

#endif // TETL_CSTRING_STRCAT_HPP
