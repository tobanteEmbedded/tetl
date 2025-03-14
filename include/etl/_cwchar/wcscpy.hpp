// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WCSCPY_HPP
#define TETL_CWCHAR_WCSCPY_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// \brief Copies the wide string pointed to by src (including the terminating
/// null wide character) to wide character array pointed to by dest.
///
/// \details The behavior is undefined if the dest array is not large enough.
/// The behavior is undefined if the strings overlap.
///
/// \returns dest
constexpr auto wcscpy(wchar_t* dest, wchar_t const* src) -> wchar_t*
{
    TETL_PRECONDITION(dest != nullptr);
    TETL_PRECONDITION(src != nullptr);
    return etl::detail::strcpy(dest, src);
}

} // namespace etl
#endif // TETL_CWCHAR_WCSCPY_HPP
