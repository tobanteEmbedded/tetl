/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_MEMCHR_HPP
#define TETL_CSTRING_MEMCHR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

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
[[nodiscard]] constexpr auto memchr(void* ptr, int ch, etl::size_t n) -> void*
{
    auto* p = static_cast<unsigned char*>(ptr);
    return detail::memchr_impl(p, static_cast<unsigned char>(ch), n);
}

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
[[nodiscard]] constexpr auto memchr(void const* ptr, int ch, etl::size_t n) -> void const*
{
    auto const* const p = static_cast<unsigned char const*>(ptr);
    auto const c        = static_cast<unsigned char>(ch);
    return detail::memchr_impl<unsigned char const, etl::size_t>(p, c, n);
}

} // namespace etl

#endif // TETL_CSTRING_MEMCHR_HPP