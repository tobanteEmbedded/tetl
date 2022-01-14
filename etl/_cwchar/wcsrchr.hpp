/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WCSRCHR_HPP
#define TETL_CWCHAR_WCSRCHR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Finds the last occurrence of the wide character ch in the wide string
/// pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcsrchr
[[nodiscard]] constexpr auto wcsrchr(wchar_t* str, int ch) -> wchar_t*
{
    return detail::strrchr_impl<wchar_t, etl::size_t>(str, ch);
}

/// \brief Finds the last occurrence of the wide character ch in the wide string
/// pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcsrchr
[[nodiscard]] constexpr auto wcsrchr(wchar_t const* str, int ch) -> wchar_t const*
{
    return detail::strrchr_impl<wchar_t const, etl::size_t>(str, ch);
}
} // namespace etl
#endif // TETL_CWCHAR_WCSRCHR_HPP