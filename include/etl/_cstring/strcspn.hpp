// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRCSPN_HPP
#define TETL_CSTRING_STRCSPN_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Returns the length of the maximum initial segment of the byte string
/// pointed to by dest, that consists of only the characters not found in byte
/// string pointed to by src.
///
/// The function name stands for "complementary span"
///
/// https://en.cppreference.com/w/cpp/string/byte/strcspn
///
/// \ingroup cstring
[[nodiscard]] constexpr auto strcspn(char const* dest, char const* src) noexcept -> etl::size_t
{
    return etl::cstr::strspn<char, etl::size_t, false>(dest, src);
}

} // namespace etl

#endif // TETL_CSTRING_STRCSPN_HPP
