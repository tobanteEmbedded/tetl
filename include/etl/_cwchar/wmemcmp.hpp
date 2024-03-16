// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WMEMCMP_HPP
#define TETL_CWCHAR_WMEMCMP_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr_algorithm.hpp>

namespace etl {

/// \brief Compares the first count wide characters of the wide character arrays
/// pointed to by lhs and rhs. The comparison is done lexicographically.
///
/// \details The sign of the result is the sign of the difference between the
/// values of the first pair of wide characters that differ in the arrays being
/// compared. If count is zero, the function does nothing.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemcmp
constexpr auto wmemcmp(wchar_t const* lhs, wchar_t const* rhs, etl::size_t count) noexcept -> int
{
    return detail::strncmp_impl<wchar_t, etl::size_t>(lhs, rhs, count);
}
} // namespace etl

#endif // TETL_CWCHAR_WMEMCMP_HPP
