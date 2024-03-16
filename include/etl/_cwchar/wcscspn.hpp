// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WCSCSPN_HPP
#define TETL_CWCHAR_WCSCSPN_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr_algorithm.hpp>

namespace etl {

/// \brief Returns the length of the maximum initial segment of the wide string
/// pointed to by dest, that consists of only the characters not found in wide
/// string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcscspn
[[nodiscard]] constexpr auto wcscspn(wchar_t const* dest, wchar_t const* src) noexcept -> etl::size_t
{
    return detail::str_span_impl<wchar_t, etl::size_t, false>(dest, src);
}
} // namespace etl

#endif // TETL_CWCHAR_WCSCSPN_HPP
