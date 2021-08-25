/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRNCAT_HPP
#define TETL_CSTRING_STRNCAT_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Appends a byte string pointed to by src to a byte string pointed to
/// by dest. At most count characters are copied. The resulting byte string is
/// null-terminated.
///
/// \details The destination byte string must have enough space for the contents
/// of both dest and src plus the terminating null character, except that the
/// size of src is limited to count. The behavior is undefined if the strings
/// overlap.
/// \module Strings
constexpr auto strncat(char* dest, char const* src, etl::size_t const count)
    -> char*
{
    return detail::strncat_impl<char, etl::size_t>(dest, src, count);
}

} // namespace etl

#endif // TETL_CSTRING_STRNCAT_HPP