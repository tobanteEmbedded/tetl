// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRSTR_HPP
#define TETL_CSTRING_STRSTR_HPP

#include <etl/_strings/cstr.hpp>

namespace etl {

/// \ingroup cstring
/// @{

/// Finds the first occurrence of the byte string needle in the byte
/// string pointed to by haystack. The terminating null characters are not
/// compared.
/// \ingroup cstring
[[nodiscard]] constexpr auto strstr(char* haystack, char* needle) noexcept -> char*
{
    return etl::detail::strstr_impl<char>(haystack, needle);
}

[[nodiscard]] constexpr auto strstr(char const* haystack, char const* needle) noexcept -> char const*
{
    return etl::detail::strstr_impl<char const>(haystack, needle);
}

/// @}

} // namespace etl

#endif // TETL_CSTRING_STRSTR_HPP
