// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRLEN_HPP
#define TETL_CSTRING_STRLEN_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Returns the length of the C string str.
constexpr auto strlen(char const* str) -> etl::size_t { return detail::strlen_impl<char, etl::size_t>(str); }

} // namespace etl

#endif // TETL_CSTRING_STRLEN_HPP
