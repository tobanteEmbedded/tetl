// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WCSLEN_HPP
#define TETL_CWCHAR_WCSLEN_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {
/// \brief Returns the length of a wide string, that is the number of non-null
/// wide characters that precede the terminating null wide character.
constexpr auto wcslen(wchar_t const* str) -> size_t { return detail::strlen<wchar_t, size_t>(str); }
} // namespace etl

#endif // TETL_CWCHAR_WCSLEN_HPP
