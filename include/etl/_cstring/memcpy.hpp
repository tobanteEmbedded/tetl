// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_MEMCPY_HPP
#define TETL_CSTRING_MEMCPY_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may not overlap. If source and destination
/// might overlap, memmove() must be used instead.
/// \ingroup cstring
inline auto memcpy(void* dest, void const* src, etl::size_t n) -> void*
{
#if defined(__clang__)
    return __builtin_memcpy(dest, src, n);
#else
    return detail::memcpy<unsigned char, etl::size_t>(dest, src, n);
#endif
}

} // namespace etl

#endif // TETL_CSTRING_MEMCPY_HPP
