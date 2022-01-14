/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRLEN_HPP
#define TETL_CSTRING_STRLEN_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Returns the length of the C string str.
constexpr auto strlen(char const* str) -> etl::size_t { return detail::strlen_impl<char, etl::size_t>(str); }

} // namespace etl

#endif // TETL_CSTRING_STRLEN_HPP