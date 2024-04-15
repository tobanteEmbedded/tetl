// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRSPN_HPP
#define TETL_CSTRING_STRSPN_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Returns the length of the maximum initial segment (span) of the byte
/// string pointed to by dest, that consists of only the characters found in
/// byte string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/byte/strspn
///
/// \ingroup cstring
[[nodiscard]] constexpr auto strspn(char const* dest, char const* src) noexcept -> etl::size_t
{
    return etl::cstr::strspn<char, etl::size_t, true>(dest, src);
}

} // namespace etl

#endif // TETL_CSTRING_STRSPN_HPP
