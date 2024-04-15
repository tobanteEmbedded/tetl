// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRRCHR_HPP
#define TETL_CSTRING_STRRCHR_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// \ingroup cstring
/// @{

/// Finds the last occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strrchr
///
/// \ingroup cstring
[[nodiscard]] constexpr auto strrchr(char const* str, int ch) noexcept -> char const*
{
    return etl::detail::strrchr<char const, etl::size_t>(str, ch);
}

[[nodiscard]] constexpr auto strrchr(char* str, int ch) noexcept -> char*
{
    return etl::detail::strrchr<char, etl::size_t>(str, ch);
}

/// @}

} // namespace etl

#endif // TETL_CSTRING_STRRCHR_HPP
