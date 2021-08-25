/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRNCMP_HPP
#define TETL_CSTRING_STRNCMP_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Compares at most count characters of two possibly null-terminated
/// arrays. The comparison is done lexicographically. Characters following the
/// null character are not compared.
///
/// \details The behavior is undefined when access occurs past the end of either
/// array lhs or rhs. The behavior is undefined when either lhs or rhs is the
/// null pointer.
/// \module Strings
constexpr auto strncmp(
    char const* lhs, char const* rhs, etl::size_t const count) -> int
{
    return detail::strncmp_impl<char, etl::size_t>(lhs, rhs, count);
}

} // namespace etl

#endif // TETL_CSTRING_STRNCMP_HPP