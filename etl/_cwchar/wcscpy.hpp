/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WCSCPY_HPP
#define TETL_CWCHAR_WCSCPY_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

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
    TETL_ASSERT(dest != nullptr && src != nullptr);
    return detail::strcpy_impl(dest, src);
}

} // namespace etl
#endif // TETL_CWCHAR_WCSCPY_HPP