/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WMEMSET_HPP
#define TETL_CWCHAR_WMEMSET_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Copies the wide character ch into each of the first count wide
/// characters of the wide character array pointed to by dest.
///
/// \details If overflow occurs, the behavior is undefined. If count is zero,
/// the function does nothing.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemset
constexpr auto wmemset(wchar_t* dest, wchar_t ch, etl::size_t count) noexcept -> wchar_t*
{
    return detail::memset_impl(dest, ch, count);
}
} // namespace etl

#endif // TETL_CWCHAR_WMEMSET_HPP