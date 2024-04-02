// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRNCMP_HPP
#define TETL_CSTRING_STRNCMP_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr_algorithm.hpp>

namespace etl {

/// Compares at most count characters of two possibly null-terminated
/// arrays. The comparison is done lexicographically. Characters following the
/// null character are not compared.
///
/// The behavior is undefined when access occurs past the end of either
/// array lhs or rhs. The behavior is undefined when either lhs or rhs is the
/// null pointer.
///
/// \ingroup cstring
constexpr auto strncmp(char const* lhs, char const* rhs, etl::size_t const count) -> int
{
    return detail::strncmp_impl<char, etl::size_t>(lhs, rhs, count);
}

} // namespace etl

#endif // TETL_CSTRING_STRNCMP_HPP
