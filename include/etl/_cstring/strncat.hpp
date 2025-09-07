// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CSTRING_STRNCAT_HPP
#define TETL_CSTRING_STRNCAT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Appends a byte string pointed to by src to a byte string pointed to
/// by dest. At most count characters are copied. The resulting byte string is
/// null-terminated.
///
/// The destination byte string must have enough space for the contents
/// of both dest and src plus the terminating null character, except that the
/// size of src is limited to count. The behavior is undefined if the strings
/// overlap.
///
/// \ingroup cstring
constexpr auto strncat(char* dest, char const* src, etl::size_t const count) -> char*
{
    return etl::detail::strncat<char, etl::size_t>(dest, src, count);
}

} // namespace etl

#endif // TETL_CSTRING_STRNCAT_HPP
