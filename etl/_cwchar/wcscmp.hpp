/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WCSCMP_HPP
#define TETL_CWCHAR_WCSCMP_HPP

#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {
/// \brief Compares two null-terminated wide strings lexicographically.
///
/// \details The sign of the result is the sign of the difference between the
/// values of the first pair of wide characters that differ in the strings being
/// compared.
///
/// The behavior is undefined if lhs or rhs are not pointers to null-terminated
/// wide strings.
[[nodiscard]] constexpr auto wcscmp(wchar_t const* lhs, wchar_t const* rhs) -> int
{
    return detail::strcmp_impl<wchar_t>(lhs, rhs);
}
} // namespace etl
#endif // TETL_CWCHAR_WCSCMP_HPP