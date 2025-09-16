// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CSTRING_MEMCHR_HPP
#define TETL_CSTRING_MEMCHR_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// \ingroup cstring
/// @{

/// \brief Converts ch to unsigned char and locates the first occurrence of that
/// value in the initial count characters (each interpreted as unsigned char) of
/// the object pointed to by ptr.
///
/// \details This function behaves as if it reads the characters sequentially
/// and stops as soon as a matching character is found: if the array pointed to
/// by ptr is smaller than count, but the match is found within the array, the
/// behavior is well-defined.
///
/// https://en.cppreference.com/w/cpp/string/byte/memchr
///
/// \returns Pointer to the location of the character, or a null pointer if no
/// such character is found.
/// \ingroup cstring
[[nodiscard]] inline auto memchr(void* ptr, int ch, etl::size_t n) -> void*
{
#if __has_builtin(__builtin_memchr)
    return __builtin_memchr(ptr, ch, n);
#else
    auto* p = static_cast<unsigned char*>(ptr);
    return etl::detail::memchr(p, static_cast<unsigned char>(ch), n);
#endif
}

[[nodiscard]] inline auto memchr(void const* ptr, int ch, etl::size_t n) -> void const*
{
#if __has_builtin(__builtin_memchr)
    return __builtin_memchr(ptr, ch, n);
#else
    auto const* const p = static_cast<unsigned char const*>(ptr);
    auto const c        = static_cast<unsigned char>(ch);
    return etl::detail::memchr<unsigned char const, etl::size_t>(p, c, n);
#endif
}

/// @}

} // namespace etl

#endif // TETL_CSTRING_MEMCHR_HPP
