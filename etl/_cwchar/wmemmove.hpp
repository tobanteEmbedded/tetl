/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WMEMMOVE_HPP
#define TETL_CWCHAR_WMEMMOVE_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Copies exactly count successive wide characters from the wide
/// character array pointed to by src to the wide character array pointed to by
/// dest.
///
/// \details If count is zero, the function does nothing. The arrays may
/// overlap: copying takes place as if the wide characters were copied to a
/// temporary wide character array and then copied from the temporary array to
/// dest. This function is not locale-sensitive and pays no attention to the
/// values of the wchar_t objects it copies: nulls as well as invalid characters
/// are copied too.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemmove
constexpr auto wmemmove(wchar_t* dest, wchar_t const* src, etl::size_t count) noexcept -> wchar_t*
{
    return detail::memmove_impl<wchar_t, etl::size_t>(dest, src, count);
}
} // namespace etl
#endif // TETL_CWCHAR_WMEMMOVE_HPP
