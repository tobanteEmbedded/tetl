// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRCPY_HPP
#define TETL_CSTRING_STRCPY_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Copies the character string pointed to by src, including the null
/// terminator, to the character array whose first element is pointed to by
/// dest.
///
/// The behavior is undefined if the dest array is not large enough.
/// The behavior is undefined if the strings overlap.
///
/// \returns dest
/// \ingroup cstring
constexpr auto strcpy(char* dest, char const* src) -> char*
{
    TETL_PRECONDITION(dest != nullptr);
    TETL_PRECONDITION(src != nullptr);
    return etl::detail::strcpy(dest, src);
}

} // namespace etl

#endif // TETL_CSTRING_STRCPY_HPP
