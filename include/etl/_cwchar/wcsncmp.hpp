// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WCSNCMP_HPP
#define TETL_CWCHAR_WCSNCMP_HPP

#include <etl/_cassert/macro.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr_algorithm.hpp>

namespace etl {

/// \brief Compares at most count wide characters of two null-terminated wide
/// strings. The comparison is done lexicographically.
///
/// \details The sign of the result is the sign of the difference between the
/// values of the first pair of wide characters that differ in the strings being
/// compared.
///
/// The behavior is undefined if lhs or rhs are not pointers to null-terminated
/// strings.
[[nodiscard]] constexpr auto wcsncmp(wchar_t const* lhs, wchar_t const* rhs, etl::size_t count) -> int
{
    return detail::strncmp_impl<wchar_t, etl::size_t>(lhs, rhs, count);
}

} // namespace etl
#endif // TETL_CWCHAR_WCSNCMP_HPP
