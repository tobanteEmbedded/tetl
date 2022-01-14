/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WMEMCHR_HPP
#define TETL_CWCHAR_WMEMCHR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Locates the first occurrence of wide character ch in the initial
/// count wide characters of the wide character array pointed to by ptr.
///
/// \details If count is zero, the function returns a null pointer.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemchr
[[nodiscard]] constexpr auto wmemchr(wchar_t* ptr, wchar_t ch, etl::size_t count) noexcept -> wchar_t*
{
    return detail::memchr_impl<wchar_t>(ptr, ch, count);
}

/// \brief Locates the first occurrence of wide character ch in the initial
/// count wide characters of the wide character array pointed to by ptr.
///
/// \details If count is zero, the function returns a null pointer.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemchr
[[nodiscard]] constexpr auto wmemchr(wchar_t const* ptr, wchar_t ch, etl::size_t count) noexcept -> wchar_t const*
{
    return detail::memchr_impl<wchar_t const>(ptr, ch, count);
}
} // namespace etl

#endif // TETL_CWCHAR_WMEMCHR_HPP