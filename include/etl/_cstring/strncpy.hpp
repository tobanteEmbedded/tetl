// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRNCPY_HPP
#define TETL_CSTRING_STRNCPY_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Copies at most count characters of the byte string pointed to by src
/// (including the terminating null character) to character array pointed to by
/// dest.
///
/// If count is reached before the entire string src was copied, the
/// resulting character array is not null-terminated. If, after copying the
/// terminating null character from src, count is not reached, additional null
/// characters are written to dest until the total of count characters have
/// been written. If the strings overlap, the behavior is undefined.
///
/// \returns dest
/// \ingroup cstring
constexpr auto strncpy(char* dest, char const* src, etl::size_t const count) -> char*
{
    TETL_PRECONDITION(dest != nullptr);
    TETL_PRECONDITION(src != nullptr);
    return detail::strncpy(dest, src, count);
}

} // namespace etl

#endif // TETL_CSTRING_STRNCPY_HPP
