/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WCSNCPY_HPP
#define TETL_CWCHAR_WCSNCPY_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Copies at most count characters of the wide string pointed to by src
/// (including the terminating null wide character) to wide character array
/// pointed to by dest.
///
/// \details If count is reached before the entire string src was copied, the
/// resulting character array is not null-terminated. If, after copying the
/// terminating null character from src, count is not reached, additional null
/// characters are written to dest until the total of count characters have
/// been written. If the strings overlap, the behavior is undefined.
///
/// \returns dest
constexpr auto wcsncpy(wchar_t* dest, wchar_t const* src, etl::size_t const count) -> wchar_t*
{
    TETL_ASSERT(dest != nullptr && src != nullptr);
    return detail::strncpy_impl(dest, src, count);
}

} // namespace etl

#endif // TETL_CWCHAR_WCSNCPY_HPP