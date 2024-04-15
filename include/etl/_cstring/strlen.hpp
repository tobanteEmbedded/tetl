// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRLEN_HPP
#define TETL_CSTRING_STRLEN_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Returns the length of the C string str.
/// \ingroup cstring
[[nodiscard]] constexpr auto strlen(char const* str) -> etl::size_t
{
#if defined(__clang__)
    return __builtin_strlen(str);
#else
    return etl::cstr::strlen<char, etl::size_t>(str);
#endif
}

} // namespace etl

#endif // TETL_CSTRING_STRLEN_HPP
