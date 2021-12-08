/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WCSLEN_HPP
#define TETL_CWCHAR_WCSLEN_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {
/// \brief Returns the length of a wide string, that is the number of non-null
/// wide characters that precede the terminating null wide character.
///
/// \module Strings
constexpr auto wcslen(wchar_t const* str) -> etl::size_t { return detail::strlen_impl<wchar_t, etl::size_t>(str); }
} // namespace etl

#endif // TETL_CWCHAR_WCSLEN_HPP