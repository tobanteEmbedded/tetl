// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WCSPBRK_HPP
#define TETL_CWCHAR_WCSPBRK_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Finds the first character in wide string pointed to by dest, that is
/// also in wide string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
[[nodiscard]] constexpr auto wcspbrk(wchar_t* dest, wchar_t* breakset) noexcept -> wchar_t*
{
    return detail::strpbrk_impl<wchar_t, etl::size_t>(dest, breakset);
}

/// \brief Finds the first character in wide string pointed to by dest, that is
/// also in wide string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
[[nodiscard]] constexpr auto wcspbrk(wchar_t const* dest, wchar_t const* breakset) noexcept -> wchar_t const*
{
    return detail::strpbrk_impl<wchar_t const, etl::size_t>(dest, breakset);
}

} // namespace etl
#endif // TETL_CWCHAR_WCSPBRK_HPP
