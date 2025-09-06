// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CWCHAR_WCSSPN_HPP
#define TETL_CWCHAR_WCSSPN_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// \brief Returns the length of the maximum initial segment of the wide string
/// pointed to by dest, that consists of only the characters found in wide
/// string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcsspn
[[nodiscard]] constexpr auto wcsspn(wchar_t const* dest, wchar_t const* src) noexcept -> etl::size_t
{
    return etl::detail::strspn<wchar_t, etl::size_t, true>(dest, src);
}
} // namespace etl

#endif // TETL_CWCHAR_WCSSPN_HPP
