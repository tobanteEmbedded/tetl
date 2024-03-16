// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_STRCMP_HPP
#define TETL_CSTRING_STRCMP_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr_algorithm.hpp>

namespace etl {

/// \brief Compares the C string lhs to the C string rhs.
///
/// \details This function starts comparing the first character of each string.
/// If they are equal to each other, it continues with the following pairs until
/// the characters differ or until a terminating null-character is reached.
constexpr auto strcmp(char const* lhs, char const* rhs) -> int { return detail::strcmp_impl<char>(lhs, rhs); }

} // namespace etl

#endif // TETL_CSTRING_STRCMP_HPP
