// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WCSSTR_HPP
#define TETL_CWCHAR_WCSSTR_HPP

#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Finds the first occurrence of the wide string needle in the wide
/// string pointed to by haystack. The terminating null characters are not
/// compared.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
[[nodiscard]] constexpr auto wcsstr(wchar_t* haystack, wchar_t* needle) noexcept -> wchar_t*
{
    return detail::strstr_impl<wchar_t>(haystack, needle);
}

/// \brief Finds the first occurrence of the wide string needle in the wide
/// string pointed to by haystack. The terminating null characters are not
/// compared.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
[[nodiscard]] constexpr auto wcsstr(wchar_t const* haystack, wchar_t const* needle) noexcept -> wchar_t const*
{
    return detail::strstr_impl<wchar_t const>(haystack, needle);
}
} // namespace etl
#endif // TETL_CWCHAR_WCSSTR_HPP
