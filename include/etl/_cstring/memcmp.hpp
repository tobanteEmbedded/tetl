// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_MEMCMP_HPP
#define TETL_CSTRING_MEMCMP_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Reinterprets the objects pointed to by lhs and rhs as arrays of
/// unsigned char and compares the first count bytes of these arrays.
/// The comparison is done lexicographically.
///
/// https://en.cppreference.com/w/cpp/string/byte/memcmp
///
/// \ingroup cstring
[[nodiscard]] inline auto memcmp(void const* lhs, void const* rhs, etl::size_t count) noexcept -> int
{
#if defined(__clang__)
    return __builtin_memcmp(lhs, rhs, count);
#else
    auto const* l = static_cast<unsigned char const*>(lhs);
    auto const* r = static_cast<unsigned char const*>(rhs);
    return etl::cstr::strncmp<unsigned char, etl::size_t>(l, r, count);
#endif
}

} // namespace etl

#endif // TETL_CSTRING_MEMCMP_HPP
