/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WCSCAT_HPP
#define TETL_CWCHAR_WCSCAT_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {
/// \brief Appends a copy of the wide string pointed to by src to the end of the
/// wide string pointed to by dest. The wide character src[0] replaces the null
/// terminator at the end of dest. The resulting wide string is null-terminated.
///
/// \details The behavior is undefined if the destination array is not large
/// enough for the contents of both src and dest and the terminating null
/// character. The behavior is undefined if the strings overlap.
constexpr auto wcscat(wchar_t* dest, wchar_t const* src) -> wchar_t*
{
    return detail::strcat_impl<wchar_t, etl::size_t>(dest, src);
}
} // namespace etl

#endif // TETL_CWCHAR_WCSCAT_HPP